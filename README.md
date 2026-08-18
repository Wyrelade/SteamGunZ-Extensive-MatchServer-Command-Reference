# Steam GunZ — Extensive Match-Server (`:6000`) Command Reference

**Game:** GUNZ: The Duel (Steam / Masang / Ludenus) — client build `1.0.0.290`, launcher version `1.3.2`
**Scope:** the TCP **match server** protocol on port `:6000` (protocol version **58**), **and** the
peer-to-peer **UDP** mesh that carries in-game movement / aim / fire (see §8).
**Source:** live sessions decoded byte-exact. See [`CORPUS_master_s52.txt`](CORPUS_master_s52.txt) for the
raw hexdumps + full wire timeline this document summarizes.

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
| 1711 | 0x06af | MC_MATCH_REQUEST_CREATE_CHAR | C2S | 48 | create a char (name + appearance) |
| 1712 | 0x06b0 | MC_MATCH_RESPONSE_CREATE_CHAR | S2C | 24 | create result (echoes name) |
| 1713 | 0x06b1 | MC_MATCH_REQUEST_DELETE_CHAR | C2S | 25 | delete a char (confirm by typed name) |
| 1714 | 0x06b2 | MC_MATCH_RESPONSE_DELETE_CHAR | S2C | 12 | delete result |
| 1717 | 0x06b5 | MC_MATCH_REQUEST_CHARINFO_DETAIL | C2S | 21..24 | ask another player's detailed char info |
| 1718 | 0x06b6 | MC_MATCH_RESPONSE_CHARINFO_DETAIL | S2C | 265 | detailed char info reply |
| 1719 | 0x06b7 | MC_MATCH_REQUEST_ACCOUNT_CHARINFO | C2S | 5 | ask for a slot's char info (param: slot) |
| 1720 | 0x06b8 | MC_MATCH_RESPONSE_ACCOUNT_CHARINFO | S2C | 559 | char detail (542-byte record). NB: the **top-right banner** name/Lv/EXP is **not** this — it's the EOS/account display-name from the auth shim (`game_info.json`), not the match server |
| 1803 | 0x070b | MC_MATCH_REQUEST_MY_SIMPLE_CHARINFO | C2S | 12 | quick self char summary |
| 1804 | 0x070c | MC_MATCH_RESPONSE_MY_SIMPLE_CHARINFO | S2C | 61 | self summary reply |
| 1722 | 0x06ba | *(UNIDENTIFIED)* | S2C | 16 | post-select notify |
| 1724 | 0x06bc | *(UNIDENTIFIED)* | S2C | 28 | post-select notify |
| 1727 | 0x06bf | *(UNIDENTIFIED)* | C2S | 12 | char request |
| 1728 | 0x06c0 | *(UNIDENTIFIED)* | S2C | 12 | char reply |

**Char-list order:** `1701` → `1702`. **Select:** `1703` → `1704` (+ `1719`→`1720` for the detail).
**Create:** `1711` → `1712` → client re-lists (`1701`→`1702`). **Delete:** `1713` → `1714` → client re-lists.

### Decoded structure — `1711` CREATE_CHAR (C2S) / `1713` DELETE_CHAR (C2S) — byte-exact
Both are keyed by the selected-account handle and a slot index; strings are `[u16 len][CP949 bytes]`
(NUL-padded to `len`).
```
1711 REQUEST_CREATE_CHAR (44 params):
+0x00  u64   accountMUID         (the account handle; low = 0x00079d3b in the capture)
+0x08  u32   slotIndex           (target bottom-bar slot, e.g. 3)
+0x0C  u16   nameLen             (e.g. 14)
+0x0E  char  name[nameLen]       (new char name, NUL-terminated — e.g. "IWillEndThis")
+..    u32   appearance          (sex/costume selector, e.g. 0x00000162)
+..    byte  reserved[...]        (remaining appearance bytes, zero in the capture)

1712 RESPONSE_CREATE_CHAR (20 params):  [u32 result=0][u16 nameLen][char name[]]   (echoes the new name)

1713 REQUEST_DELETE_CHAR (21 params):
+0x00  u64   accountMUID         (low = 0x00079d3b)
+0x08  u32   slotIndex           (the char being deleted, e.g. 2)
+0x0C  u16   nameLen             (7)
+0x0E  char  name[nameLen]       (the char's own name, re-typed to confirm — e.g. "test5")

1714 RESPONSE_DELETE_CHAR (8 params):   [u32 result=0][u32 deletedCharId]           (result 0 = success)
```
> Deletion is a **confirm-by-name** action: the client makes you re-type the exact character name, and sends
> that string in `1713` alongside the slot. The server validates it matches the char in that slot before
> deleting. `result=0` in `1714` = deleted; the client then re-requests `1701`→`1702` to refresh the bar.

### Decoded structure — `1702` char-list record (46 bytes each) — byte-exact, 3-char capture
BlobArray payload = `u32 payloadLen | u32 elementSize=46 | u32 elementCount | record[0] | record[1] | ...`
(`payloadLen = 8 + count*46`). Each 46-byte record:
```
+0x00  u32   characterId
+0x04  char  name[32]        (CP949, NUL-padded, ≤31 bytes)
+0x24  u8    slotIndex       (0,1,2… = bottom-bar order)
+0x25  u8    level
+0x26  u32   charNum         (secondary id; 0 on empty slot)
+0x2A  byte  reserved[4]
```
Real example (account "Wyrelade"): 3 records — `Wyrelade` (slot 0, lvl 8) · `StrikeGZ` (slot 1, lvl 1) ·
`test5` (slot 2, lvl 1). `elementCount = 3`.

### Decoded structure — `1720` / `1704` char detail (542-byte record) — byte-exact
`1720 RESPONSE_ACCOUNT_CHARINFO` params = `[u32 ~550][u32 542][u32 count=1][542-byte record]`.
`1704 RESPONSE_SELECT_CHAR` params = `[u32 result=0][u32 550][u32 542][u32 1][542-byte record]` (same record,
prefixed with the result word). Record head:
```
+0x00 name[32] | +0x20 clanName[16] | +0x30 i32 clanGrade | +0x34 u16 clanContribution |
+0x36 u8 slotIndex | +0x37 u16 level | +0x39 u8 sex | +0x3A u8 hair | +0x3B u8 face |
+0x3C u32 experience | +0x40 u32 bounty (= DB Character.BP / the "BT" currency) |
```
Deeper in the SAME record (our packer historically **zeroes** these — they must be filled for appearance +
select-commit):
```
≈+0x7C u32  equippedItemID[12]   (one per MMCIP equip slot — the appearance ids; e.g. 0x2f4d63, 0x2f7479,
                                  0x2fc2a1, 0x2f9bc7, 0x2fe9cf, 0x30d400, 0x30d401, 0x1e8480, 0x1f6ee0,
                                  0x1fe414, 0x2191c3, 0x2191c4)
≈+0xD8 u32  colorOrClanMuid[3]   (e.g. 0x5d6241, 0x5d1423, 0x5d3b31)
```
`1704` additionally carries, after the record, an **equipped-instance MUID array** — the *instance* ids of
the currently-worn items (e.g. `0x00104f55 / 5a / 5b / 5c`), i.e. the specific stash items that are equipped
(these instance ids come from the `1832` account list and the `1833` bring-to-char moves).

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
| 1811 | 0x0713 | MC_MATCH_REQUEST_BUY_ITEM | C2S | 29 | buy an item (shop selector) |
| 1812 | 0x0714 | MC_MATCH_RESPONSE_BUY_ITEM | S2C | ~1320 | buy result **+ the rebuilt item list bundled in** |
| 1813 | 0x0715 | MC_MATCH_REQUEST_SELL_ITEM | C2S | 8 | sell an owned item |
| 1814 | 0x0716 | MC_MATCH_RESPONSE_SELL_ITEM | S2C | 20 | sell result (+ new balance) |
| 1823 | 0x071f | MC_MATCH_REQUEST_EQUIP_ITEM | C2S | 24 | equip an item instance into a slot |
| 1824 | 0x0720 | MC_MATCH_RESPONSE_EQUIP_ITEM | S2C | 8 | equip result (new equip state) |
| 1825 | 0x0721 | MC_MATCH_REQUEST_TAKEOFF_ITEM | C2S | 16 | **unequip** — take an item off a slot |
| 1826 | 0x0722 | MC_MATCH_RESPONSE_TAKEOFF_ITEM | S2C | 8 | unequip result |
| 1831 | 0x0727 | MC_MATCH_REQUEST_ACCOUNT_ITEMLIST | C2S | 12 | **"give me my account stash"** (the real Hideout inventory) |
| 1832 | 0x0728 | MC_MATCH_RESPONSE_ACCOUNT_ITEMLIST | S2C | var (16-B recs) | **account item list** — what the Hideout inventory renders |
| 1833 | 0x0729 | MC_MATCH_REQUEST_BRING_ACCOUNT_ITEM | C2S | 24 | move an item **stash → character** (makes it worn/usable) |
| 1836 | 0x072c | MC_MATCH_RESPONSE_BRING_BACK_ACCOUNTITEM | S2C | ~606 | rebuilt char + item detail after the move |
| 1822 | 0x071e | MC_MATCH_RESPONSE_CHARACTER_ITEMLIST | S2C | 663..1562 | *(alt/legacy)* per-char item list — **NOT** the retail Hideout path (see below) |
| 21000 | 0x5208 | MC_MATCH_REQUEST_CHAR_QUEST_ITEM_LIST | C2S | 12 | quest-item list request |
| 21001 | 0x5209 | MC_MATCH_RESPONSE_CHAR_QUEST_ITEM_LIST | S2C | 16 | quest-item list reply |
| 21002 | 0x520a | MC_MATCH_REQUEST_BUY_QUEST_ITEM | C2S | var | buy a quest item |
| 21003 | 0x520b | MC_MATCH_RESPONSE_BUY_QUEST_ITEM | S2C | var | buy-quest-item result |

> **Retail inventory correction (byte-exact from a live retail session).** The Hideout inventory is driven by the
> **account item list** (`1831`→`1832`) and **bring-to-character** (`1833`→`1836`), *not* by `1822`. On login
> the client asks `1831`; the server answers `1832` with the account **stash** (16-byte records). To put an
> item on the character (so it's worn / equippable), the client sends `1833 BRING_ACCOUNT_ITEM` and the
> server replies `1836` with the rebuilt detail. `1822 RESPONSE_CHARACTER_ITEMLIST` still exists and decodes,
> but the retail Steam client does **not** use it to fill the Hideout inventory grid — an emulator that only
> pushes `1822` shows an **empty** inventory. Implement `1831/1832` (+ `1833/1836`) to match retail.

**Flows:** inventory `1831`→`1832`; equip `1823`→`1824`; unequip `1825`→`1826`; buy `1811`→`1812`;
sell `1813`→`1814`; bring-to-char `1833`→`1836`.

### Decoded structure — `1832` RESPONSE_ACCOUNT_ITEMLIST (the real inventory)
```
params:
+0x00  u32   lead            (MUID low / flags)
+0x04  u32   payloadLen      (bytes of the blob that follows = 8 + count*16)
+0x08  u32   elementSize=16
+0x0C  u32   count
+0x10  ...   count × 16-byte item record:
             +0x00 u32 itemInstanceLow   (unique id of this owned item, e.g. 0x0004 2fb6)
             +0x04 u32 itemID            (retail catalog id, e.g. 0x0f4247, 0x5d145b, 0x5d3b55)
             +0x08 u32 rentMinPeriod     (0x00080520 = 525600 = UNLIMITED = permanent; smaller = rental)
             +0x0C u32 count             (stack count, usually 1)
```

### Decoded structure — `1833` REQUEST_BRING_ACCOUNT_ITEM (stash → char)
```
+0x00  u64   charMUID        (the selected char handle; low = 0x00079d3b in the capture)
+0x08  u32   itemInstanceLow (which stash item — matches a 1832 record's +0x00)
+0x0C  u32   itemID          (matches that record's itemID)
+0x10  u32   qty             (1)
```
Server applies the move, then replies `1836` (rebuilt char/item detail) so the item shows on the character.

### Decoded structure — `1811` REQUEST_BUY_ITEM (25 params B, real)
```
+0x00  u32   0
+0x04  u32   shopSelector    (e.g. 0x01d905ca — a shop-slot token, NOT a raw catalog itemID)
+0x08  u32   1
+0x0C  u32   2
+0x10  u32   0x22000002      (category/filter word)
+0x14  u32   3
+0x18  u8    0
```
`shopSelector` maps to a catalog `itemID` via the retail **`GShop.xml`** `SHOP_ITEM.ID → ITEM_ID` table
(client `system.mrs`); the match server never sends a shop catalog. Dev sandbox ignores cost.

### Decoded structure — `1812` RESPONSE_BUY_ITEM (~1316 params B, real)
```
+0x00  u32   result=0
+0x04  u32   echo            (= the 1811 shopSelector)
+0x08  ...   the rebuilt owned-item list (~1300 B) bundled straight into the buy response
```
> The buy response is **not** a bare 7-byte ack (the earlier corpus guess) — retail bundles the updated item
> list into `1812`, so after a purchase the client refreshes inventory from this one response.

### Decoded structure — `1823` / `1825` equip / unequip
```
1823 REQUEST_EQUIP_ITEM (20 params):  [u64 charMUID][u32 itemInstanceLow][u32 0][u32 slot]   (equip by instance→slot)
1824 RESPONSE_EQUIP_ITEM (4 params):  [u32 newEquipState]                                    (e.g. 0x00004e23)
1825 REQUEST_TAKEOFF_ITEM (12 params):[u64 charMUID][u32 slot]                               (unequip by slot)
1826 RESPONSE_TAKEOFF_ITEM (4 params):[u32 result=0]
```
> **Profile picture / frame / icon changes use this same equip path.** Changing your profile image is just
> `1823` equipping a *profile* item instance into its slot — observed slots **7** and **8** (profile
> icon / frame) and **20** (profile background). There is no dedicated "set profile picture" command; each
> change is one `1823`→`1824` with the chosen item's instance id and the profile slot number.

**`1822` RESPONSE_CHARACTER_ITEMLIST layout (alt/legacy path, `phase26_parse1822.py`):**
`[207-B header][ N × 29-B item record ][16-B trailer]`. Header = `[u32 @0 (varies: 0x44/0x5e/0x6c…)]`
`[const `00 00 00 b8 00 00 00 08 00 00 00 16` @4]` `[3-B pad]` `[equip-slot MUID table: MMCIP_END(12)`
`slots × (u32 instLow + u32 instHigh=0), 0=empty]` `[zeros/fields]`. Each 29-B record:
```
+0x00 u32 itemInstanceID   +0x04 u32 instHigh(=0)   +0x08 u32 itemID (retail catalog)
+0x0C u32 rentMinRemainder (0x80520 = 525600 = RENT_MINUTE_PERIOD_UNLIMITED = PERMANENT; smaller = rental)
+0x10 u32 fB (0x48 rental / 0 permanent)   +0x14 u32 count   +0x18 u32 expiryTs (0 = permanent)   +0x1C u8 0
```
Kept for reference (the record layout is genuine), but the retail Hideout grid reads `1832`, not this.

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
| 1225 | 0x04c9 | MC_MATCH_CHANNEL_REQUEST_CHAT | C2S | 28 | **send** a channel chat line |
| 1226 | 0x04ca | MC_MATCH_CHANNEL_CHAT | S2C | 65..90 | a chat line broadcast (sender + text) |
| 1231 | 0x04cf | MC_MATCH_CHANNEL_RESPONSE_RULE | S2C | 16 | channel rule info |

**Flow:** `1211`→`1213`(list) ; `1205`→`1207`(join) ; `1221`→`1222`(who) ; `1225`(send chat)→`1226`(broadcast).

### Decoded structure — chat (byte-exact)
```
1225 REQUEST_CHANNEL_CHAT (C2S, 24 params):
+0x00  u64   charMUID        (low = 0x00079d3b)
+0x08  u32   chatType        (1)
+0x0C  u32   reserved (0)
+0x10  u16   textLen
+0x12  char  text[textLen]   (CP949, NUL-terminated — e.g. "easy")

1226 CHANNEL_CHAT (S2C, ~62 params):
+0x00  u64   senderMUID
+0x08  u16   nameLen
+..    char  senderName[]    (e.g. "Czar")
+..    u16   textLen
+..    char  text[]          (CP949; Korean jamo etc. pass through as multi-byte)
```
Room/stage chat is the separate `1321 MC_MATCH_STAGE_CHAT` (C2S, §5): `[u64 charMUID][u16 len][text]`.

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
| 22002 | 0x55f2 | *(reward list — see §11)* | S2C | 854 | reward/event list push |
| 22117 | 0x5665 | *(UNIDENTIFIED)* | S2C | 8 | notify |

---

## 10. Friends

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 1901 | 0x076d | MC_MATCH_FRIEND_ADD | C2S | 16 | add a friend **by name** |
| 1903 | 0x076f | MC_MATCH_FRIEND_LIST | C2S | 4 | request the friend list (param-less) |

### Decoded structure — `1901` FRIEND_ADD (byte-exact)
```
+0x00  u16   nameLen         (e.g. 10)
+0x02  char  name[nameLen]   (the account/char name to befriend, CP949 — e.g. "wyrelade")
```
Friends are added **by name string**, not by MUID. `1903` (list) is sent with no params; the server
answers with the current friend roster.

---

## 11. Rewards, achievements & quest items (login gifts / event claims)

The Steam client shows event-reward, achievement, and "quest item" panels. Each panel is **opened** with a
tiny param-less `C2S` request and **filled** by a large `S2C` push carrying the reward text + the grantable
items; a reward is **claimed** with a quest-item buy.

| id | hex | name | dir | body | what it does |
|----|-----|------|-----|------|--------------|
| 19015 | 0x4a47 | *(reward list request)* | C2S | 4 | open a reward/event panel (param-less) |
| 19012 | 0x4a44 | *(reward list)* | S2C | 854 | reward/event list + description text + grantable items |
| 21997 | 0x55ed | *(reward list request)* | C2S | 4 | open a reward panel (param-less) |
| 21998 | 0x55ee | *(reward list)* | S2C | 854 | reward list (same 854-B shape as 19012) |
| 22001 | 0x55f1 | *(reward list request)* | C2S | 4 | open a reward panel (param-less) |
| 22002 | 0x55f2 | *(reward list)* | S2C | 854 | reward list |
| 22043 | 0x561b | *(reward list request)* | C2S | 4 | open a reward panel (param-less) |
| 21000 | 0x5208 | MC_MATCH_REQUEST_CHAR_QUEST_ITEM_LIST | C2S | 12 | `[u64 charMUID]` — list this char's quest items |
| 21001 | 0x5209 | MC_MATCH_RESPONSE_CHAR_QUEST_ITEM_LIST | S2C | 16 | quest-item list |
| 21002 | 0x520a | MC_MATCH_REQUEST_BUY_QUEST_ITEM | C2S | 20 | **claim / redeem a quest (achievement/event) item** |
| 21003 | 0x520b | MC_MATCH_RESPONSE_BUY_QUEST_ITEM | S2C | 20 | claim result (grants the item instance) |
| 20965 | 0x51e5 | *(achievement claim)* | C2S | 20 | achievement-reward claim (secondary account MUID) |
| 20984 | 0x51f8 | *(achievement result)* | S2C | 24 | achievement claim result (→ char MUID) |
| 20985 | 0x51f9 | *(achievement claim)* | C2S | 12 | achievement claim step |
| 20986 | 0x51fa | *(achievement result)* | S2C | 41 | achievement claim result |
| 20987 | 0x51fb | *(achievement claim)* | C2S | 20 | achievement claim step |

### Decoded structure — claiming a reward item (`21002` → `21003`)
```
21002 REQUEST_BUY_QUEST_ITEM (16 params):
+0x00  u64   charMUID        (low = 0x00079d3b)
+0x08  u32   questItemID     (the reward's catalog id — e.g. 0x00030d41)
+0x0C  u32   count           (1)

21003 RESPONSE_BUY_QUEST_ITEM (16 params):
+0x00  u32   result=0
+0x04  u32   newInstanceId   (the granted owned-item instance, e.g. 0x00004cc8)
+0x08  byte  reserved[...]
```
> Flow observed: open panel (param-less `19015`/`21997`/`22001`/`22043` → 854-B list) → pick a reward →
> `21002` with the item's `questItemID` → `21003 result=0` grants a fresh item instance, which then appears
> in the account item list (`1832`) and can be brought to the character (`1833`) and equipped (`1823`).
> Achievement rewards additionally use the `20965/20984/20985/20986/20987` cluster (a secondary account
> MUID `…0x5a91…` appears in those requests). The 854-B reward push carries the human text seen in-game
> (e.g. *"Wishlist Reward — … Gender-specific items will be provided based on your character's gender"* and
> *"Thanks for Joining GunZ — … a special profile image to commemorate the moment"*).

---

## Unidentified command ids (need naming)
These decode cleanly (valid MCommand framing) but aren't in the stock table — new Steam/Masang additions.
Their byte layouts are in the corpus; meaning is inferred from when they appear:

`1335, 1337, 1404, 1418, 1424, 1443, 1445, 1722, 1724, 1727, 1728, 1845, 1848, 1853, 1854, 1886, 1889,
1890, 2303, 2307, 3200, 3202, 3203, 3204, 3206, 5004, 9301, 22117`

High-value ones to identify next: **1424** (per-player room state), **9301** (very frequent broadcast),
**3200/3202** (Steam-state pair), **1335** (large room bulk).

---

## Provenance
The `:6000` corpus ([`CORPUS_master_s52.txt`](CORPUS_master_s52.txt)) is included in this repo. The §8 P2P/UDP
mesh is derived from live match captures.

*Generated 2026-08-17 from decoded live sessions. `:6000` command names come from the MAIET stock command
table; §8 peer names are inferred from wire behaviour (volume, direction, float layout). Descriptions of
UNIDENTIFIED ids are best-effort from wire context and may be refined as more is decoded.*
