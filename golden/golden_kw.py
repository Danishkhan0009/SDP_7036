#!/usr/bin/env python3
"""
golden_kw.py - Golden model for standby key custody (Spec v1.0, Section 6, Task 3).

  D9 : KEK = KBKDF counter mode, PRF = AES-CMAC (NIST SP 800-108r1 sec 4.1)
       KEK_s = CMAC(root, [1]_32 || "IME-STBY" || 0x00 || epoch_32 || slot_8 || [128]_32)
  D10: blob_s = AES-KW(KEK_s, K1 || K2)  (RFC 3394 / SP 800-38F KW) -> 320 bits per slot
       K1 round-10 key is recomputed on wake, not wrapped.
  Epoch: 32-bit AON counter, +1 on every standby entry BEFORE wrapping, never decremented.
  Unwrap checks the RFC 3394 integrity value A6A6A6A6A6A6A6A6; any mismatch -> reject
  (stale epoch, wrong slot, wrong root, flipped blob bit all land here).

Pure Python on top of golden_xts's AES core (no crypto library).
"""
from golden_xts import expand_key, aes_enc_block, aes_dec_block, key_slot

IV = bytes.fromhex("a6a6a6a6a6a6a6a6")
LABEL = b"IME-STBY"


# ---------------------------------------------------------------- AES-KW (RFC 3394 2.2.1/2.2.2)
def kw_wrap(kek, p):
    assert len(p) % 8 == 0 and len(p) >= 16
    rk = expand_key(kek)
    n = len(p) // 8
    a, r = IV, [p[8 * i:8 * i + 8] for i in range(n)]
    for j in range(6):
        for i in range(n):
            b = aes_enc_block(rk, a + r[i])
            t = n * j + i + 1
            a = (int.from_bytes(b[:8], "big") ^ t).to_bytes(8, "big")
            r[i] = b[8:]
    return a + b"".join(r)


def kw_unwrap(kek, c):
    """Returns plaintext key data, or None if the integrity check fails."""
    assert len(c) % 8 == 0 and len(c) >= 24
    rk = expand_key(kek)
    n = len(c) // 8 - 1
    a, r = c[:8], [c[8 * (i + 1):8 * (i + 2)] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n - 1, -1, -1):
            t = n * j + i + 1
            a_t = (int.from_bytes(a, "big") ^ t).to_bytes(8, "big")
            b = aes_dec_block(rk, a_t + r[i])
            a, r[i] = b[:8], b[8:]
    return b"".join(r) if a == IV else None


# ---------------------------------------------------------------- AES-CMAC (SP 800-38B / RFC 4493)
def _dbl(b):
    v = int.from_bytes(b, "big") << 1
    if v >> 128:
        v = (v & ((1 << 128) - 1)) ^ 0x87
    return v.to_bytes(16, "big")


def cmac(key, msg):
    rk = expand_key(key)
    k1 = _dbl(aes_enc_block(rk, bytes(16)))
    k2 = _dbl(k1)
    blocks = [msg[i:i + 16] for i in range(0, len(msg), 16)] or [b""]
    last = blocks[-1]
    if len(last) == 16 and msg:
        last = bytes(x ^ y for x, y in zip(last, k1))
    else:
        last = last + b"\x80" + bytes(15 - len(last))
        last = bytes(x ^ y for x, y in zip(last, k2))
    x = bytes(16)
    for blk in blocks[:-1] + [last]:
        x = aes_enc_block(rk, bytes(p ^ q for p, q in zip(x, blk)))
    return x


# ---------------------------------------------------------------- KBKDF (SP 800-108 counter mode)
def kbkdf_ctr_cmac(ki, label, context, out_bits=128):
    n = (out_bits + 127) // 128
    out = b""
    for i in range(1, n + 1):
        out += cmac(ki, i.to_bytes(4, "big") + label + b"\x00" + context + out_bits.to_bytes(4, "big"))
    return out[:out_bits // 8]


def derive_kek(root, epoch, slot):
    """D9: per-slot, per-epoch KEK."""
    assert len(root) == 16 and 0 <= epoch < 2 ** 32 and 0 <= slot < 4
    return kbkdf_ctr_cmac(root, LABEL, epoch.to_bytes(4, "big") + bytes([slot]))


# ---------------------------------------------------------------- standby custody model
def standby_enter(root, epoch, slots):
    """slots: list of 4 x 32-byte keys (K1||K2) or None. Returns (new_epoch, blobs)."""
    epoch += 1  # increment BEFORE wrapping: an old blob can never match the new epoch
    assert epoch < 2 ** 32, "epoch exhausted: device must refuse standby"
    blobs = [None if k is None else kw_wrap(derive_kek(root, epoch, s), k) for s, k in enumerate(slots)]
    return epoch, blobs


def standby_wake(root, epoch, blobs):
    """Returns list of key_slot dicts (K1, K1_rk10, K2) or 'REJECT' per slot."""
    out = []
    for s, b in enumerate(blobs):
        if b is None:
            out.append(None)
            continue
        k = kw_unwrap(derive_kek(root, epoch, s), b)
        out.append("REJECT" if k is None else key_slot(k))
    return out


# ---------------------------------------------------------------- self-test
RFC3394 = [  # (section, KEK, key data, ciphertext)
    ("4.1", "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
     "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
    ("4.2", "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
     "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"),
    ("4.3", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
    ("4.4", "000102030405060708090A0B0C0D0E0F1011121314151617",
     "00112233445566778899AABBCCDDEEFF0001020304050607",
     "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"),
    ("4.5", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF0001020304050607",
     "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"),
    ("4.6", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
     "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"),
]
RFC4493_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
RFC4493_MSG = ("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
RFC4493 = [(0, "bb1d6929e95937287fa37d129b756746"), (16, "070a16b46b4d4144f79bdd9dd04a287c"),
           (40, "dfa66747de9ae63030ca32611497c827"), (64, "51f0bebf7e3b9d92fc49741779363cfe")]


def self_test(verbose=True):
    ok = True

    def rep(name, r):
        nonlocal ok
        ok &= r
        if verbose:
            print(f"{name:<44}: {'PASS' if r else 'FAIL'}")

    for sec, k, p, c in RFC3394:
        k, p, c = bytes.fromhex(k), bytes.fromhex(p), bytes.fromhex(c)
        rep(f"RFC 3394 {sec} wrap/unwrap ({len(k)*8}-bit KEK, {len(p)*8}-bit data)",
            kw_wrap(k, p) == c and kw_unwrap(k, c) == p)
    key, msg = bytes.fromhex(RFC4493_KEY), bytes.fromhex(RFC4493_MSG)
    for ln, t in RFC4493:
        rep(f"RFC 4493 AES-CMAC, {ln}-byte message", cmac(key, msg[:ln]).hex() == t)

    # custody scenarios
    root = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    slots = [bytes(range(32)), bytes(range(32, 64)), None, bytes(range(64, 96))]
    e1, b1 = standby_enter(root, 0, slots)
    w = standby_wake(root, e1, b1)
    rep("Standby round trip restores K1, K1_rk10, K2", all(
        (s is None and x is None) or x == key_slot(s) for s, x in zip(slots, w)))
    rep("Blob size = 320 bits per slot", all(b is None or len(b) * 8 == 320 for b in b1))
    e2, _ = standby_enter(root, e1, slots)
    rep("Stale blob (old epoch) rejected", standby_wake(root, e2, b1)[0] == "REJECT")
    rep("Blob moved to another slot rejected", standby_wake(root, e1, [b1[1], b1[0], None, None])[0] == "REJECT")
    rep("Wrong root rejected", standby_wake(bytes(16), e1, b1)[0] == "REJECT")
    flips = 0
    for bit in range(320):
        bad = bytearray(b1[0]); bad[bit // 8] ^= 1 << (bit % 8)
        flips += kw_unwrap(derive_kek(root, e1, 0), bytes(bad)) is None
    rep("Every single-bit blob flip rejected (320/320)", flips == 320)
    rep("KEKs differ across slots and epochs", len({derive_kek(root, e, s) for e in (1, 2) for s in range(4)}) == 8)
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
