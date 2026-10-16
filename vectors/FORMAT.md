# Vector file format (auto-generated)

One record per line, hex, MSB first, as `$readmemh` expects. `// [n] label` lines are comments.

**Byte-order rule:** byte strings (data, keys, tweaks, KEK, root, blob) put byte 0 in field[7:0]. Integers (ADDR, EPOCH, SLOT, CTRL, REC, J) are plain binary values.

- CTRL = {5'b0, dir, slot[1:0]}; dir 0 = encrypt (write), 1 = decrypt (read)
- TYPE 0 = wrap (in: ROOT, EPOCH, SLOT, KEYS; expect: KEK, BLOB). TYPE 1 = unwrap (in: ROOT, EPOCH, SLOT, BLOB; expect: OK, and if OK=1 KEYS + RK10, else zeros)

## XTS (1320 bits)

| Field | Bits | Type |
| --- | --- | --- |
| CTRL | [1319:1312] | integer |
| ADDR | [1311:1280] | integer |
| K1 | [1279:1152] | byte string |
| K2 | [1151:1024] | byte string |
| DIN | [1023:512] | byte string |
| DOUT | [511:0] | byte string |

## KEYSLOT (384 bits)

| Field | Bits | Type |
| --- | --- | --- |
| K1 | [383:256] | byte string |
| K2 | [255:128] | byte string |
| RK10 | [127:0] | byte string |

## TRACE (664 bits)

| Field | Bits | Type |
| --- | --- | --- |
| REC | [663:648] | integer |
| J | [647:640] | integer |
| T | [639:512] | byte string |
| BIN | [511:384] | byte string |
| PRE | [383:256] | byte string |
| AES | [255:128] | byte string |
| BOUT | [127:0] | byte string |

## KW (1016 bits)

| Field | Bits | Type |
| --- | --- | --- |
| TYPE | [1015:1008] | integer |
| OK | [1007:1000] | integer |
| SLOT | [999:992] | integer |
| EPOCH | [991:960] | integer |
| ROOT | [959:832] | byte string |
| KEK | [831:704] | byte string |
| KEYS | [703:448] | byte string |
| RK10 | [447:320] | byte string |
| BLOB | [319:0] | byte string |
