# Steam GunZ — Extensive Match-Server (`:6000`) Command Reference

**Game:** GUNZ: The Duel (Steam / Masang / Ludenus) — client build `1.0.0.290`, launcher version `1.3.2`
**Scope:** the TCP **match server** protocol on port `:6000` (protocol version **58**), **and** the
peer-to-peer **UDP** mesh that carries in-game movement / aim / fire (see §8).
**Source:** one full live session, decoded byte-exact. See [`CORPUS_master_s52.txt`](CORPUS_master_s52.txt) for the raw hexdumps + full wire timeline this document summarizes.

> **What this is for.** Developing tools for Steam GunZ. It documents how the client and the match
> server talk on `:6000` — the wire framing, crypto, and command set — so you can build things that
> speak the protocol (emulators, decoders, proxies, analysis tooling).

---

## TL;DR — how to read & use this

1. **Every message is an `MCommand`** identified by a numeric **command id** (e.g. `1301` = create a room).
   The id tells you what it is; the body carries the fields.
2. **The wire packet** wraps that command:
   ```
   offset  size  field
   0       u16   nSize        (total packet length; ENCRYPTED with key[0..1] on 0x65 packets)
   2       u16   nMsg         (0x65=101 COMMAND / encrypted body,  0x64=100 RAWCOMMAND / plaintext body,
                               0x0A=10 REPLYCONNECT / plaintext handshake)
   4       u16   nCheckSum    (cleartext, over the packet)
   6       u8    reserved     (inert per-packet nonce; write 0)
   7..     ...   Buffer       (the MCommand body; ENCRYPTED on 0x65)
   ```
3. **The MCommand body** (what's inside `Buffer`):
   ```
   0   u16   nDataCount   (== length of the body, i.e. nSize-7)
   2   u16   commandID    (the id in the tables below)
   4   u8    serial       (Masang builds use 0 — no serial checking)
   5.. ...   parameters   (command-specific; strings are CP949, NUL-terminated/padded)
   ```
4. **Crypto:** the `0x65` body + the `nSize` field are encrypted with a per-session 32-byte key (repeats
   every 32 bytes). Byte transform: `dec(c,k) = rotr8(c ^ 0xF0, 5) ^ k`. The key is
   `MMakeSeedKey(ts, uidServer.Low, uidClient.High, uidClient.Low)` xored with a fixed 16-byte table + a
   fixed 16-byte IV. For your **own** emulator you already know the key (you generate it), so you never
   need to crack anything — just encrypt/decrypt with it. (For decoding a capture, see the tools below.)
5. **To implement a command on your server:** find its id in the tables, read the matching hexdump in the
   corpus file, mirror the field layout, and reply with the paired response id. Requests are `C2S`
   (client→server), responses are `S2C`.

**Tooling you might want (all optional)**

You do **not** need any special tool to use this document. Everything required to build an
emulator or read the corpus is specified above — the packet framing, the crypto transform, and
the command tables. For your own server you generate the session key yourself, so there is nothing
to crack, and the [`CORPUS_master_s52.txt`](CORPUS_master_s52.txt) dump is already decoded to
plaintext hex, so you can read it with any text editor. A dev might still want, and can write
from this spec in a few dozen lines:

- **A framing + crypto codec** — split the TCP stream into packets and run the `0x65`
  encrypt/decrypt (`dec(c,k) = rotr8(c ^ 0xF0, 5) ^ k`) with the session key. Needed only if you
  want to decode *your own* fresh captures; the included corpus is already plaintext.
- **A known-plaintext key recovery** — recover the 32-byte key from a *live Masang* capture where
  you don't know the seed. Only relevant for decoding third-party captures, **not** for running
  your own emulator (you already hold the key).
- **A decrypting proxy / injector** — a MITM that decodes traffic live and can inject frames.
  Handy for interop testing against a real client, but not required to read this reference.

---

## Legend
- **dir**: `C2S` client→server (a request/report), `S2C` server→client (a response/broadcast).
- **body**: length in bytes of the MCommand body (id+serial+params); a range means the payload varies.
- Names in `MC_*` come from the stock MAIET command table; **UNIDENTIFIED** = seen on the wire but not in
  the stock enum (new Masang/Steam commands — layout is in the corpus, meaning is inferred from context).

---

## 1. Session / net / login

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 322 | 0x0142 | MC_NET_PING | S2C | 8 | latency probe from server |
| 323 | 0x0143 | MC_NET_PONG | C2S | 8 | client's reply to a ping |
| 361 | 0x0169 | MC_CLOCK_SYNCHRONIZE | S2C | 8 | server clock sync value |
| 402 | 0x0192 | MC_MATCH_ANNOUNCE | S2C | 29 | server announcement / system message |
| 1002 | 0x03ea | MC_MATCH_RESPONSE_LOGIN | S2C | 40 | login result (player uid, flags) after 1017 |
| 1006 | 0x03ee | MC_MATCH_BRIDGEPEER | C2S | 20 | NAT/bridge peer info for P2P setup |
| 1007 | 0x03ef | MC_MATCH_BRIDGEPEER_ACK | S2C | 16 | ack of bridge peer |
| 1017 | 0x03f9 | MC_MATCH_LOGIN_STEAM | C2S | 731 | the big Steam login (ticket + account payload) |
| 6347 | 0x18cb | MC_MATCH_MISC_STEAM | C2S | 12 | misc Steam-state ping |
| 3201 | 0x0c81 | MC_MATCH_STATE_STEAM | C2S | 17 | periodic Steam presence/state heartbeat (very frequent) |
| 3202 | 0x0c82 | *(UNIDENTIFIED)* | S2C | 24 | server reply paired with 3201 |
| 3200 | 0x0c80 | *(UNIDENTIFIED)* | S2C | 72..3312 | bulk Steam-related state push (variable) |
| 3203 | 0x0c83 | *(UNIDENTIFIED)* | C2S | 24 | Steam-state request |
| 3204 | 0x0c84 | *(UNIDENTIFIED)* | S2C | 16 | Steam-state reply |
| 3206 | 0x0c86 | *(UNIDENTIFIED)* | S2C | 16 | Steam-state notify |

**Login order:** `1017 LOGIN_STEAM` (C2S) → `1002 RESPONSE_LOGIN` (S2C). Then char-list, channel, etc.

---

## 2. Account & character

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 1701 | 0x06a5 | MC_MATCH_REQUEST_ACCOUNT_CHARLIST | C2S | 36 | "give me my characters" |
| 1702 | 0x06a6 | MC_MATCH_RESPONSE_ACCOUNT_CHARLIST | S2C | 108..154 | the char-list (BlobArray of 46-byte records) |
| 1703 | 0x06a7 | MC_MATCH_REQUEST_SELECT_CHAR | C2S | 16 | select a character slot |
| 1704 | 0x06a8 | MC_MATCH_RESPONSE_SELECT_CHAR | S2C | 608 | selected char's full detail (542-byte record) |
| 1711 | 0x06af | MC_MATCH_REQUEST_CREATE_CHAR | C2S | 41 | create a char (name + appearance) |
| 1712 | 0x06b0 | MC_MATCH_RESPONSE_CREATE_CHAR | S2C | 17 | create result (slot/result code) |
| 1717 | 0x06b5 | MC_MATCH_REQUEST_CHARINFO_DETAIL | C2S | 21..24 | ask another player's detailed char info |
| 1718 | 0x06b6 | MC_MATCH_RESPONSE_CHARINFO_DETAIL | S2C | 265 | detailed char info reply |
| 1719 | 0x06b7 | MC_MATCH_REQUEST_ACCOUNT_CHARINFO | C2S | 5 | ask for a slot's char info (param: slot) |
| 1720 | 0x06b8 | MC_MATCH_RESPONSE_ACCOUNT_CHARINFO | S2C | 559 | char detail (542-byte record; top-right name source) |
| 1803 | 0x070b | MC_MATCH_REQUEST_MY_SIMPLE_CHARINFO | C2S | 12 | quick self char summary |
| 1804 | 0x070c | MC_MATCH_RESPONSE_MY_SIMPLE_CHARINFO | S2C | 61 | self summary reply |
| 1722 | 0x06ba | *(UNIDENTIFIED)* | S2C | 16 | post-select notify |
| 1724 | 0x06bc | *(UNIDENTIFIED)* | S2C | 28 | post-select notify |
| 1727 | 0x06bf | *(UNIDENTIFIED)* | C2S | 12 | char request |
| 1728 | 0x06c0 | *(UNIDENTIFIED)* | S2C | 12 | char reply |

**Char-list order:** `1701` → `1702`. **Select:** `1703` → `1704` (+ `1719`→`1720` for the detail).
**Create:** `1711` → `1712` → client re-lists (`1701`→`1702`).

### Decoded structure — `1702` char-list record (46 bytes each)
BlobArray payload = `u32 elementSize=46 | u32 elementCount | record[0] | record[1] | ...`
```
+0x00  u32   characterId
+0x04  char  name[32]        (CP949, NUL-padded, ≤31 bytes)
+0x24  u8    slotIndex
+0x25  u8    level
+0x26  byte  reserved[8]     (all-zero = active char)
```

### Decoded structure — `1720` / `1704` char detail (542-byte record head)
```
+0x00 name[32] | +0x20 clanName[16] | +0x30 i32 clanGrade | +0x34 u16 clanContribution |
+0x36 u8 slotIndex | +0x37 u16 level | +0x39 u8 sex | +0x3A u8 hair | +0x3B u8 face |
+0x3C u32 experience | +0x40 u32 bounty | 0x44.. stats / items / currencies / region (zero-fill)
```

**Currency map (LIVE-VERIFIED, phase-26 W1).** The retail top bar shows three currencies: **C (Coin)**,
**ZC**, **BT (Bounty)**.
- **BT (Bounty)** IS the char-record currency = record **+0x40** (= DB `Character.BP`). Setting `BP` high
  moved BT 0→nonzero live; it's the only shop currency the match server controls.
- **C (Coin)** and **ZC** are **account-level** — NOT in the 542-B char record (a distinct-marker pass at
  record +0x44/+0x48/+0x4C lit up NONE of the three), NOT in the shim `game_info.json`, NOT any DB column.
  They read as client-cached account values (e.g. C=1025, ZC=95460) from the real Steam account and persist
  until an account-currency command overrides them. Same bucket as the deferred nickname (phase-26 W0). To
  max Coin/ZC we must identify + send that account-currency command (candidate unknown ids 1722/1724/1727/
  1728/1845), not touch the char record. Shop premium packages are priced in **Coin** (e.g. 1800) → Coin
  gates "afford anything"; regular Credits-tab items are affordable at the cached ZC.
- Record +0x44/+0x48/+0x4C are pinned to dev-max as a harmless hedge (any detail panel that reads them shows
  max); +0x50 stays zero (ts/uid, not money).

---

## 3. Shop & items

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 1811 | 0x0713 | MC_MATCH_REQUEST_BUY_ITEM | C2S | 29 | buy an item (item id + duration) |
| 1812 | 0x0714 | MC_MATCH_RESPONSE_BUY_ITEM | S2C | 12 | buy result (result code + new balance) |
| 1822 | 0x071e | MC_MATCH_RESPONSE_CHARACTER_ITEMLIST | S2C | 663..1562 | your inventory item list |
| 1823 | 0x071f | MC_MATCH_REQUEST_EQUIP_ITEM | C2S | 24 | equip an item into a slot |
| 1824 | 0x0720 | MC_MATCH_RESPONSE_EQUIP_ITEM | S2C | 8 | equip result |
| 21000 | 0x5208 | MC_MATCH_REQUEST_CHAR_QUEST_ITEM_LIST | C2S | 12 | quest-item list request |
| 21001 | 0x5209 | MC_MATCH_RESPONSE_CHAR_QUEST_ITEM_LIST | S2C | 16 | quest-item list reply |

**Buy:** `1811` → `1812`. **Equip:** `1823` → `1824`. Inventory arrives as `1822` (server pushes it
unsolicited — the client never sends `1821`).

**`1811` REQUEST_BUY_ITEM body (24 params B), 5 real samples decoded as BE u32:**
`[w0 qty/low][w1 item-token …0101][w2 …02][w3 …02/9602][w4 …03/9603][w5 0]`. w1 is a per-shop-slot token
(low 2 bytes const `0101`), NOT a raw catalog itemID → mapping slot→itemID needs the retail shop catalog
(client `system.mrs`). Dev sandbox ignores cost.
**`1812` RESPONSE_BUY_ITEM (7 params B):** `[u32 result=0][3 echo bytes = 1811 body[4:7]]`. IMPLEMENTED
(phase-26 W2: raw-blob 1811 → exact 1812 success).
**`1824` RESPONSE_EQUIP_ITEM (3 params B):** `00 00 00` (result=0). IMPLEMENTED (raw-blob 1823 → 1824).

**`1822` RESPONSE_CHARACTER_ITEMLIST layout (CRACKED, `phase26_parse1822.py`):**
`[207-B header][ N × 29-B item record ][16-B trailer]`. Header = `[u32 @0 (varies: 0x44/0x5e/0x6c…)]`
`[const `00 00 00 b8 00 00 00 08 00 00 00 16` @4]` `[3-B pad]` `[equip-slot MUID table: MMCIP_END(12)`
`slots × (u32 instLow + u32 instHigh=0), 0=empty]` `[zeros/fields]`. Each 29-B record:
```
+0x00 u32 itemInstanceID   +0x04 u32 instHigh(=0)   +0x08 u32 itemID (retail catalog)
+0x0C u32 rentMinRemainder (0x80520 = 525600 = RENT_MINUTE_PERIOD_UNLIMITED = PERMANENT; smaller = rental)
+0x10 u32 fB (0x48 rental / 0 permanent)   +0x14 u32 count   +0x18 u32 expiryTs (0 = permanent)   +0x1C u8 0
```
37 real retail itemIDs mined (weapons/armor): `0x30d401 0x30d400 0x2f9b81 0x2f74a4 0x1e8480 0x602160 …`.
The 207-B header is a custom hand-packed blob (not a stock BlobArray) — reconstruct/validate it with the
`gunzemu_gui.py` injector (inject candidate 1822s at the live client, no rebuild) before baking into the
`ResponseCharacterItemList` MASANG path. That builder is where W3 inventory + equip-persistence land.

---

## 4. Channel & lobby

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 1201 | 0x04b1 | MC_MATCH_REQUEST_RECOMMANDED_CHANNEL | C2S | — | ask for the recommended channel |
| 1202 | 0x04b2 | MC_MATCH_RESPONSE_RECOMMANDED_CHANNEL | S2C | 12 | recommended channel reply |
| 1205 | 0x04b5 | MC_MATCH_CHANNEL_REQUEST_JOIN | C2S | 20 | join a channel |
| 1207 | 0x04b7 | MC_MATCH_CHANNEL_RESPONSE_JOIN | S2C | 46 | join result (channel name + rule) |
| 1211 | 0x04bb | MC_MATCH_CHANNEL_LIST_START | C2S | 16 | begin channel-list paging |
| 1213 | 0x04bd | MC_MATCH_CHANNEL_LIST | S2C | 176 | one page of channels |
| 1221 | 0x04c5 | MC_MATCH_CHANNEL_REQUEST_PLAYER_LIST | C2S | 24 | ask who's in the channel |
| 1222 | 0x04c6 | MC_MATCH_CHANNEL_RESPONSE_PLAYER_LIST | S2C | 606 | channel player list |
| 1226 | 0x04ca | MC_MATCH_CHANNEL_CHAT | S2C | 65..90 | a chat line (sender + text) |
| 1231 | 0x04cf | MC_MATCH_CHANNEL_RESPONSE_RULE | S2C | 16 | channel rule info |

**Flow:** `1211`→`1213`(list) ; `1205`→`1207`(join) ; `1221`→`1222`(who) ; `1226`(chat).

---

## 5. Stage / room (create · join · settings)

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 1301 | 0x0515 | MC_MATCH_STAGE_CREATE | C2S | 327..330 | **create a room** (name + map + mode + settings) |
| 1303 | 0x0517 | MC_MATCH_STAGE_JOIN | S2C | 34..37 | room-join notify (a player entered) |
| 1304 | 0x0518 | MC_MATCH_REQUEST_STAGE_JOIN | C2S | 12 | request to join a room |
| 1307 | 0x051b | MC_MATCH_STAGE_LEAVE | C2S/S2C | 12 | leave room / leave notify |
| 1311 | 0x051f | MC_MATCH_REQUEST_STAGE_LIST | C2S | 24 | ask for the room list |
| 1314 | 0x0522 | MC_MATCH_STAGE_LIST | S2C | 5078..5298 | the room list (all open rooms) |
| 1411 | 0x0583 | MC_MATCH_REQUEST_STAGESETTING | C2S | 12 | ask current room settings |
| 1412 | 0x0584 | MC_MATCH_RESPONSE_STAGESETTING | S2C | 383..577 | room settings (map, mode, rounds, limits) |
| 1416 | 0x0588 | MC_MATCH_STAGE_RESPONSE_FORCED_ENTRY | S2C | 8 | forced-entry result |
| 1421 | 0x058d | MC_MATCH_STAGE_MASTER | S2C | 20 | who is room master |
| 1422 | 0x058e | MC_MATCH_STAGE_PLAYER_STATE | S2C | 24 | a player's ready/team state in the room |
| 1423 | 0x058f | MC_MATCH_STAGE_TEAM | S2C | 24 | team assignment |
| 1431 | 0x0597 | MC_MATCH_STAGE_START | C2S/S2C | 8 | start the game |
| 1432 | 0x0598 | MC_MATCH_STAGE_LAUNCH | S2C | 23 | launch into the map |
| 1401 | 0x0579 | MC_MATCH_STAGE_REQUEST_ENTERBATTLE | C2S | 12 | request to enter battle |
| 1402 | 0x057a | MC_MATCH_STAGE_ENTERBATTLE | S2C | 579 | enter-battle payload (peer/game info) |
| 1403 | 0x057b | MC_MATCH_STAGE_LEAVEBATTLE | C2S | 5 | leave battle back to room |
| 1441 | 0x05a1 | MC_MATCH_LOADING_COMPLETE | C2S/S2C | 16 | map loaded / all-loaded |
| 1442 | 0x05a2 | MC_MATCH_STAGE_FINISH_GAME | S2C | 13 | game over → back to room |
| 1451 | 0x05ab | MC_MATCH_REQUEST_GAME_INFO | C2S | 12 | request game info |
| 1404 | 0x057c | *(UNIDENTIFIED)* | S2C | 13 | room notify |
| 1418 | 0x058a | *(UNIDENTIFIED)* | S2C | 36 | room notify |
| 1424 | 0x0590 | *(UNIDENTIFIED)* | S2C | 44 | per-player room state (frequent) |
| 1443 | 0x05a3 | *(UNIDENTIFIED)* | C2S | 148 | client game report |
| 1445 | 0x05a5 | *(UNIDENTIFIED)* | S2C | 12 | game notify |
| 1335 | 0x0537 | *(UNIDENTIFIED)* | S2C | 1996..6616 | large room/list bulk push |
| 1337 | 0x0539 | *(UNIDENTIFIED)* | C2S | 56 | room/list request |

**Create-room flow (observed):** `1304 REQUEST_STAGE_JOIN` / `1301 STAGE_CREATE` → `1411`→`1412`(settings)
→ `1415 FORCED_ENTRY` → `1401`→`1402`(enter battle) → `1441 LOADING_COMPLETE` → `1431 STAGE_START`.

### Decoded structure — `1301` STAGE_CREATE body (C2S)
```
+0x00  char   roomName[...]   (NUL-terminated string, e.g. "asdasdasd")
+..    flags/limits           (u16 player limit, u32 flags — see corpus offsets 11..36)
+0x25  char   mapName[...]     (NUL-terminated, e.g. "Mansion")  ← map is a NAME string
+..    settings               (game type, rounds, time, password bytes; trailing bytes may be
                               uninitialized client stack padding — do not treat as meaningful)
```

---

## 6. In-game / combat

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 1501 | 0x05dd | MC_MATCH_GAME_ROUNDSTATE | S2C | 28 | round state (countdown/active/end + scores) |
| 1511 | 0x05e7 | MC_MATCH_GAME_KILL | C2S | 20 | client reports a kill (attacker/victim/weapon) |
| 1512 | 0x05e8 | MC_MATCH_GAME_DEAD | S2C | 28 | authoritative death broadcast |
| 1513 | 0x05e9 | MC_MATCH_GAME_LEVEL_UP | S2C | 16 | level-up notify |
| 1515 | 0x05eb | MC_MATCH_GAME_REQUEST_SPAWN | C2S | 36 | request to spawn |
| 1516 | 0x05ec | MC_MATCH_GAME_RESPONSE_SPAWN | S2C | 24 | spawn grant (position/team) |
| 1521 | 0x05f1 | MC_MATCH_GAME_REQUEST_TIMESYNC | C2S | 8 | time-sync request |
| 1522 | 0x05f2 | MC_MATCH_GAME_RESPONSE_TIMESYNC | S2C | 12 | time-sync reply |
| 1523 | 0x05f3 | MC_MATCH_GAME_REPORT_TIMESYNC | C2S | 12 | client time report |
| 1541 | 0x0605 | MC_MATCH_REQUEST_OBTAIN_WORLDITEM | C2S | 16 | pick up a world item (HP/AP/ammo) |
| 1542 | 0x0606 | MC_MATCH_OBTAIN_WORLDITEM | S2C | 16 | world-item obtained broadcast |
| 1543 | 0x0607 | MC_MATCH_SPAWN_WORLDITEM | S2C | 28..52 | world item spawned on the map |
| 2101 | 0x0835 | MC_MATCH_NOTIFY_CALLVOTE | S2C | 45 | a vote was called |
| 2102 | 0x0836 | MC_MATCH_NOTIFY_VOTERESULT | S2C | 28 | vote result |
| 2202 | 0x089a | MC_MATCH_BROADCAST_DUEL_RENEW_VICTORIES | S2C | 38..42 | duel win-streak update |
| 2203 | 0x089b | MC_MATCH_BROADCAST_DUEL_INTERRUPT_VICTORIES | S2C | 30..32 | duel streak broken |

> **Note on movement.** Player **position / aiming / firing motion is peer-to-peer (UDP)**, not on this
> TCP `:6000` stream. Only server-authoritative events (spawn, kill/death, round state, world items) go
> through the match server. That UDP peer traffic is now captured and decoded — see **§8** for the port,
> framing, and the movement / aim / fire command ids.

**Combat flow:** `1515`→`1516`(spawn) → play → `1511 KILL`(report) → `1512 DEAD`(authoritative) →
respawn (`1515`) ; `1501 ROUNDSTATE` drives round transitions ; `1543`/`1541`→`1542` world items.

---

## 7. Peer / relay (P2P setup)

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 1461 | 0x05b5 | MC_MATCH_REQUEST_PEERLIST | C2S | 12 | ask for the peer list of the game |
| 1462 | 0x05b6 | MC_MATCH_RESPONSE_PEERLIST | S2C | 2834..6206 | peer list (addresses for P2P) |
| 1471 | 0x05bf | MC_MATCH_REQUEST_PEER_RELAY | C2S | 12 | request relay when P2P fails |
| 1472 | 0x05c0 | MC_MATCH_RESPONSE_PEER_RELAY | S2C | 12 | relay grant |
| 5061 | 0x13c5 | MC_AGENT_LOCATETO_CLIENT | S2C | 43 | relay-agent locate info |

---

## 8. P2P / UDP peer mesh — movement · aim · fire  (in-game motion)

The motion that the TCP `:6000` stream does **not** carry (see the movement note in §6) travels here: a
peer-to-peer **UDP** mesh between the players in a game. Section 7 is the *setup* (the match server hands
out peer addresses on TCP); this section is the *motion* those peers then exchange directly over UDP.

**Transport.** The client binds a local UDP socket on port **`7727`**; peers and the relay-agent are on
ports **`7600`–`7799`**. When direct peer-to-peer fails NAT, the game falls back to a **relay-agent**
(a Cloudflare host on `…:7778`, same network as the match server) that forwards every peer's state — so in
a relayed session all inbound motion arrives from that one agent address, not from the individual peer IPs.
The bare NAT hole-punch (`10005`) is still sent directly to each peer.

**Framing — same `MCommand`, but plaintext.** A peer datagram uses the **identical wire header** as a
`:6000` packet (`nSize`, `nMsg`, `nCheckSum`, reserved byte, then the body), except `nMsg = 0x64`
**RAWCOMMAND** — the body is **cleartext, never encrypted**. There is **no P2P crypto and no key**: just
split and read. One datagram may carry **more than one** `MCommand` back-to-back, each framed by its own
`nDataCount`. Every peer command ends with a `u32` **timestamp** (milliseconds, monotonically increasing)
so receivers can order and interpolate state. Positions, aim, and shot vectors are **world-space
`float32`**.

| id | hex | name (inferred) | dir | body | what it does |
|----|-----|-----------------|-----|------|--------------|
| 5082 | 0x13da | PEER_MOVE_BROADCAST | C2S | 36..72 | **our** per-frame movement/state broadcast (highest-volume command in a match) |
| 15003 | 0x3a9b | PEER_BASICINFO | S2C | 44 | a **peer's** movement (world position + packed velocity/direction) |
| 15004 | 0x3a9c | PEER_AIM | S2C | 16 | a peer's **aim** (pitch + yaw) |
| 15007 | 0x3a9f | PEER_SHOT | S2C | 28 | a peer **fires** (shot origin + direction) |
| 15019 | 0x3aab | PEER_DAMAGE | S2C | 20 | a **hit lands** — carries the per-hit **damage magnitude** (13, 17, 30, 69…) |
| 15005 | 0x3a9d | *(peer event)* | S2C | 32 | in-game peer state (position + correction, 2 timestamps) |
| 15008 | 0x3aa0 | *(peer event)* | S2C | 26 | in-game peer state (carries a 32-bit hash/uid field) |
| 15009 | 0x3aa1 | *(peer event)* | S2C | 12 | weapon / anim state (small enum 7..11) |
| 15001 / 15002 | 0x3a99 / 0x3a9a | PEER_SEQ/ACK | S2C | 12 | rolling sequence/ack token (reliability over UDP) |
| 15010..15018 | 0x3aa2..0x3aaa | *(peer events)* | S2C | 8..32 | reload / melee / misc peer events |
| 10005 | 0x2715 | PEER_NATPUNCH | C2S | 0 | bare hello, spammed direct to each peer to open NAT |
| 10007 → 10008 | 0x2717 / 0x2718 | AGENT_HANDSHAKE | C2S / S2C | 4 / 8 | relay-agent handshake (carries a session UID) |

### Decoded structure — `15004` PEER_AIM (16-byte body)
```
+0x00  f32   pitch          (aim angle, world-space)
+0x04  f32   yaw            (aim angle, world-space)
+0x08  u32   timestamp      (ms, increasing)
+0x0C  u32   reserved (0)
```

### Decoded structure — `15007` PEER_SHOT (28-byte body)
```
+0x00  f32   originX        ) shot origin in world space
+0x04  f32   originY        )
+0x08  f32   originZ        )
+0x0C  f32   direction      (aim/spread component)
+0x10  u32   reserved (0)
+0x14  u32   timestamp      (ms)
```

### Decoded structure — `15019` PEER_DAMAGE (20-byte body)
```
+0x00  u32   timestamp      (ms — when the shot was fired)
+0x04  u32   reserved (0)
+0x08  u32   damage         (per-hit magnitude; observed 2,13,16,17,28,30,36,54,63,69,80)
+0x0C  u32   timestamp      (ms — when the hit is applied; the pair brackets lag-comp)
+0x10  u32   reserved (0)
```
> Value distribution over one match (n=1375): `13`×1203, then `30, 17, 28, 69, 16, 36, 54, 80…` — the
> shape of weapon damage (a spammed primary at 13, melee ~30, headshots 69/80), not a counter.

### Decoded structure — `15003` PEER_BASICINFO / movement (44-byte body)
```
+0x00  u32   flags/subtype
+0x04  f32   posX           (world position; e.g. 253.70, 312.6 across peers)
+0x08  ...   packed i16     (velocity + facing/aim direction, compressed as int16s)
+..    u32   timestamp      (ms) at the tail, followed by a u32 pad
```

### Decoded structure — `5082` our movement broadcast (36..72-byte body)
```
+0x00  f32   header         (constant marker)
+0x04  u32   senderUID      (our peer uid, e.g. 0x00251bcc)
+0x08  u32   reserved (0)
+0x0C  u32   timestamp      (ms)
+0x10  ...   state          (movement/position/anim state; grows toward 72 B for the full-position form)
```

**Motion flow (in a game):** you broadcast `5082` every frame; each peer's `15003` (move) + `15004` (aim)
stream in continuously; `15007` fires on each shot; `15019` lands the damage; the `15001/2/5/8/9…` cluster
carries the remaining per-peer events (sequence/ack, reload, melee, weapon state). The server-authoritative
outcomes (spawn/kill/death/round) stay on TCP `:6000` in §6 — so a full picture of a fight = `:6000` §6
**plus** this UDP mesh.

### Damage & HP model (there is no "total damage" packet)
GunZ combat is **peer-authoritative and per-hit** — nothing on the wire ever carries a running/total damage
or an HP value:
- **Damage is per-hit only.** A hit is a single `15019` event carrying just that hit's magnitude (e.g. 13).
  There is no aggregate. HP lives **only in each client's local simulation**: the victim subtracts the
  incoming `15019` damage from its own HP. No client ever transmits its HP total.
- **The server never sees damage or HP.** The match server (`:6000`) only learns the *outcome*: `1511
  MC_MATCH_GAME_KILL` (client-reported) → `1512 MC_MATCH_GAME_DEAD` (authoritative broadcast). Everything
  between spawn and death — every hit, every HP change — happens on this UDP mesh, invisible to `:6000`.
  This is the classic GunZ "host-advantage" design: whoever's client resolves the hit first wins the trade.
- **Direction is asymmetric under relay.** Outbound, the client sends only `5082` (its own muxed state) to
  the agent; inbound, the agent forwards every *other* peer's typed events (`15003/4/7/19…`). So the damage
  you **take** arrives as `15019`; the damage you **deal** is resolved on the victim's side from your shot.

### `5082` is a relay envelope — the outbound peer commands live *inside* it
The `5082` broadcast is **not a leaf command**. It is a **relay envelope** that tunnels one or more **nested
MCommands** to the relay agent (`…:7778`), sent **once per destination peer**. The client keeps the stock
MAIET **10000-range `MC_PEER_*` command ids**; the agent re-numbers them into the `15xxx` range when it
forwards them to other peers (a per-id lookup, *not* a fixed offset — e.g. `10032 → 15019`, `10012 →
15003`). So the outbound half of every fight — the shots, melee swings, and damage **you deal** — is carried
here, nested, and was previously seen only as the opaque `5082` blob.

```
5082 body:
+0x00  f32   header         (constant marker)
+0x04  u32   senderUID      (our peer uid, e.g. 0x00251bcc)
+0x08  u32   reserved (0)
+0x0C  u32   destPeerUID    (recipient; one 5082 is emitted per peer)
+0x10  u32   reserved (0)
+0x14  u32   blockLen       (byte length of the nested-command region)
+0x18  u32   seq
+0x1C  u32   nCmds          (count of nested MCommands that follow)
+0x20  ...   nested MCommands, each: [u16 nDataCount][u16 innerID][payload]
                             (nDataCount = 4 + payload length)
```

**Nested peer commands (C2S, wire-confirmed; names from the MAIET/OpenGunZ stock table):**

| id | hex | name | body | layout |
|----|-----|------|------|--------|
| 10012 | 0x271c | MC_PEER_BASICINFO | 35 | position / velocity / state |
| 10014 | 0x271e | MC_PEER_HPAPINFO | 8 | `[f32 hp][f32 ap]` |
| 10022 | 0x2726 | MC_PEER_CHANGE_WEAPON | 4 | `[u32 slot]` |
| 10032 | 0x2730 | MC_PEER_DAMAGE | 12 | `[u32 victimUID.Low][u32 victimUID.High][u32 damage]` |
| 10033 | 0x2731 | MC_PEER_RELOAD | 0 | — |
| 10034 | 0x2732 | MC_PEER_SHOT | 17 | packed shot info (origin / direction / sel) |
| 10037 | 0x2735 | MC_PEER_SHOT_MELEE | 20 | `[f32 shotTime][f32 x][f32 y][f32 z][u32 nShot]` |
| 10045 | 0x273d | MC_PEER_DASH | 15 | dash vector |
| 10041 | 0x2739 | MC_PEER_DIE | 8 | `[u32 UID.Low][u32 UID.High]` |
| 10001 / 10002 | 0x2711 / 0x2712 | MC_PEER_PING / PONG | 12 | clock sync |

### Decoded structure — `MC_PEER_SHOT_MELEE` / sword swing (`0x2735`, 20-byte body)
```
+0x00  f32   shotTime       (game time in seconds; increases across the match)
+0x04  f32   posX           ) attacker world position at the swing
+0x08  f32   posY           )
+0x0C  f32   posZ           )
+0x10  u32   nShot          (combo/swing index: 0,1,2…)
```
This command carries the **swing animation only** — it deals no damage on its own.

### Decoded structure — `MC_PEER_DAMAGE` / the hit that lands (`0x2730`, 12-byte body)
```
+0x00  u32   victimUID.Low  ) target peer MUID
+0x04  u32   victimUID.High )
+0x08  u32   damage         (raw magnitude: sword 30, primary 13, headshot 69/80)
```
The attacker sends this **directly to the victim**, whose client runs `OnDamage(sender, victim, damage)` and
subtracts HP from its **own local simulation** — with no server validation and no hit-geometry check. The
match server (`:6000`) sees only the post-hoc `1511 KILL` → `1512 DEAD`.

### Exploitation — turning peer-authoritative damage to advantage
Because damage is a raw integer the victim applies unconditionally, the combat model is directly abusable:
- **One-shot / burst kill.** Emit `MC_PEER_DAMAGE` = `[victimUID.Low][victimUID.High][100]` (or the target's
  full HP) at a peer → instant death. Repeat at 60–100 Hz for continuous "slash-spam" pressure independent of
  range or aim. Pair it with a genuine `MC_PEER_SHOT_MELEE` so the swing looks legitimate.
- **No line-of-sight or range required.** `MC_PEER_DAMAGE` carries no origin, direction, or hit geometry — the
  victim has nothing to validate against and cannot reject it. Any peer UID from the room roster
  (`1462 RESPONSE_PEERLIST`) is a valid target.
- **Sender is the envelope, not the payload.** `OnDamage` trusts `pCommand->GetSenderUID()` — the `5082`
  `senderUID` / relay session — so hits can be attributed at will.
- **Delivery.** Craft the nested record, wrap it in the `5082` envelope, and send it UDP from `:7727` to the
  relay agent `:7778` (or directly to a peer `:76xx` when NAT is open). The mesh is plaintext (`nMsg = 0x64`),
  so no crypto is involved.

---

## 9. Clan / misc / other

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 1101 | 0x044d | MC_MATCH_OBJECT_CACHE | S2C | 17..3033 | object/asset cache sync |
| 1605 | 0x0645 | MC_MATCH_USER_OPTION | C2S | 8 | user option toggle |
| 2051 | 0x0803 | MC_MATCH_CLAN_REQUEST_EMBLEMURL | C2S | 20 | ask for a clan emblem URL |
| 2052 | 0x0804 | MC_MATCH_CLAN_RESPONSE_EMBLEMURL | S2C | 16 | clan emblem URL reply |
| 5004 | 0x138c | *(UNIDENTIFIED)* | S2C | 544 | bulk push |
| 1845 | 0x0735 | *(UNIDENTIFIED)* | S2C | 140 | item/shop related |
| 1848 | 0x0738 | *(UNIDENTIFIED)* | S2C | 20 | item related |
| 1853 / 1854 | 0x073d / 0x073e | *(UNIDENTIFIED)* | C2S / S2C | 8 / 20 | request/reply pair |
| 1886 | 0x075e | *(UNIDENTIFIED)* | S2C | 8 | frequent notify (heartbeat-like) |
| 1889 / 1890 | 0x0761 / 0x0762 | *(UNIDENTIFIED)* | C2S / S2C | 8 / 12 | request/reply pair |
| 2303 | 0x08ff | *(UNIDENTIFIED)* | S2C | 32 | notify |
| 2307 | 0x0903 | *(UNIDENTIFIED)* | S2C | 24 | notify |
| 9301 | 0x2455 | *(UNIDENTIFIED)* | S2C | 44 | very frequent broadcast (per-player tick?) |
| 22002 | 0x55f2 | *(UNIDENTIFIED)* | S2C | 854 | large one-shot push (login-time table) |
| 22117 | 0x5665 | *(UNIDENTIFIED)* | S2C | 8 | notify |

---

## Unidentified command ids (need naming)
These decode cleanly (valid MCommand framing) but aren't in the stock table — new Steam/Masang additions.
Their byte layouts are in the corpus; meaning is inferred from when they appear:

`1335, 1337, 1404, 1418, 1424, 1443, 1445, 1722, 1724, 1727, 1728, 1845, 1848, 1853, 1854, 1886, 1889,
1890, 2303, 2307, 3200, 3202, 3203, 3204, 3206, 5004, 9301, 22002, 22117`

High-value ones to identify next: **1424** (per-player room state), **9301** (very frequent broadcast),
**3200/3202** (Steam-state pair), **1335** (large room bulk).

---

## Provenance
The `:6000` corpus ([`CORPUS_master_s52.txt`](CORPUS_master_s52.txt)) is included in this repo. The §8 P2P/UDP
mesh is derived from live match captures.

*Generated 2026-08-17 from decoded live sessions. `:6000` command names come from the MAIET stock command
table; §8 peer names are inferred from wire behaviour (volume, direction, float layout). Descriptions of
UNIDENTIFIED ids are best-effort from wire context and may be refined as more is decoded.*
