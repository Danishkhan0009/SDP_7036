#!/usr/bin/env python3
"""
golden_xts.py - Golden reference model for the IME engine (Spec v1.0, Section 1).

XTS-AES-128 per IEEE 1619-2007, pure Python, no crypto libraries, so it is an
independent reference for the RTL (OpenSSL is used only to cross-check it).

Engine conventions (Spec Section 1, D1-D5):
  - Key = K1 || K2 (K1 encrypts data, K2 encrypts the tweak). Engine rejects K1 == K2.
  - Data unit = one 64 B line = 4 blocks (j = 0..3). No ciphertext stealing.
  - Tweak input i = physical line address, 128-bit LITTLE-endian
    (address 1 -> bytes 01 00 .. 00).
  - Key slot stores K1, K1 round-10 key, K2 (decrypt starts from round-10 key).

API:
  xts_encrypt(key32, i, pt, strict=False, trace=None) -> ct
  xts_decrypt(key32, i, ct, strict=False, trace=None) -> pt
    i     : int (sequence number / line address) or 16 bytes (raw tweak value)
    strict: True = reject K1 == K2 like the engine does
    trace : list -> per-block records appended for RTL debug
  key_slot(key32) -> dict with K1, K1_rk10, K2 (what the RTL key slot holds)
"""

# ---------------------------------------------------------------- AES-128 core
SBOX = [0] * 256
INV_SBOX = [0] * 256


def _xt(a):  # multiply by x in GF(2^8)
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xt(a)
        b >>= 1
    return r


def _build_sbox():
    # S-box from the field inverse + affine map (FIPS-197 5.1.1), not a typed table
    for x in range(256):
        inv = 0
        if x:
            for y in range(1, 256):
                if _gmul(x, y) == 1:
                    inv = y
                    break
        s = inv
        for k in range(1, 5):
            s ^= ((inv << k) | (inv >> (8 - k))) & 0xFF
        s ^= 0x63
        SBOX[x] = s
        INV_SBOX[s] = x


_build_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def expand_key(key):
    """AES key schedule (FIPS-197 5.2). 16/24/32-byte key -> 11/13/15 round keys.
    The engine datapath uses AES-128 only; 192/256 exist so RFC 3394 vectors 4.2-4.6
    can check the key-wrap logic."""
    nk = len(key) // 4
    assert len(key) in (16, 24, 32)
    nr = nk + 6
    w = [list(key[4 * n:4 * n + 4]) for n in range(nk)]
    for n in range(nk, 4 * (nr + 1)):
        t = list(w[n - 1])
        if n % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[n // nk - 1]
        elif nk > 6 and n % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[n - nk], t)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(nr + 1)]


def _add(s, rk):
    return [a ^ b for a, b in zip(s, rk)]


def _shift(s, inv=False):
    o = [0] * 16
    for c in range(4):
        for r in range(4):
            src = (c - r) % 4 if inv else (c + r) % 4
            o[4 * c + r] = s[4 * src + r]
    return o


def _mix(s, inv=False):
    m = [14, 11, 13, 9] if inv else [2, 3, 1, 1]
    o = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            o[4 * c + r] = (_gmul(col[0], m[(0 - r) % 4]) ^ _gmul(col[1], m[(1 - r) % 4]) ^
                            _gmul(col[2], m[(2 - r) % 4]) ^ _gmul(col[3], m[(3 - r) % 4]))
    return o


def aes_enc_block(rks, blk):
    nr = len(rks) - 1
    s = _add(list(blk), rks[0])
    for r in range(1, nr + 1):
        s = [SBOX[b] for b in s]
        s = _shift(s)
        if r != nr:
            s = _mix(s)
        s = _add(s, rks[r])
    return bytes(s)


def aes_dec_block(rks, blk):
    nr = len(rks) - 1
    s = _add(list(blk), rks[nr])
    for r in range(nr - 1, -1, -1):
        s = _shift(s, inv=True)
        s = [INV_SBOX[b] for b in s]
        s = _add(s, rks[r])
        if r != 0:
            s = _mix(s, inv=True)
    return bytes(s)


# ---------------------------------------------------------------- XTS
def tweak_bytes(i):
    """int -> 16-byte little-endian tweak value; bytes pass through."""
    if isinstance(i, int):
        return i.to_bytes(16, "little")
    assert len(i) == 16
    return bytes(i)


def mul_alpha(t):
    """T * alpha in GF(2^128), IEEE 1619 byte order: shift left 1, XOR 0x87 on carry."""
    v = int.from_bytes(t, "little") << 1
    if v >> 128:
        v = (v & ((1 << 128) - 1)) ^ 0x87
    return v.to_bytes(16, "little")


def _split(key32, strict):
    assert len(key32) == 32, "XTS-AES-128 key is 32 bytes (K1 || K2)"
    k1, k2 = key32[:16], key32[16:]
    if strict and k1 == k2:
        raise ValueError("K1 == K2 rejected (engine rule, FIPS 140-3 IG C.I)")
    return k1, k2


def _xts(key32, i, data, enc, strict, trace):
    if len(data) % 16:
        raise ValueError("data must be whole 16 B blocks (engine has no ciphertext stealing)")
    k1, k2 = _split(key32, strict)
    rk1, rk2 = expand_key(k1), expand_key(k2)
    t = aes_enc_block(rk2, tweak_bytes(i))  # tweak is ALWAYS AES-encrypt
    out = b""
    for j in range(len(data) // 16):
        blk = data[16 * j:16 * j + 16]
        pp = bytes(a ^ b for a, b in zip(blk, t))
        cc = aes_enc_block(rk1, pp) if enc else aes_dec_block(rk1, pp)
        ob = bytes(a ^ b for a, b in zip(cc, t))
        if trace is not None:
            trace.append({"j": j, "T": t.hex(), "in": blk.hex(), "pre": pp.hex(),
                          "aes": cc.hex(), "out": ob.hex()})
        out += ob
        t = mul_alpha(t)
    return out


def xts_encrypt(key32, i, pt, strict=False, trace=None):
    return _xts(key32, i, pt, True, strict, trace)


def xts_decrypt(key32, i, ct, strict=False, trace=None):
    return _xts(key32, i, ct, False, strict, trace)


def key_slot(key32):
    """What one RTL key slot holds (Spec D5): K1, K1 round-10 key, K2 = 384 bits."""
    k1, k2 = _split(key32, strict=True)
    return {"K1": k1.hex(), "K1_rk10": expand_key(k1)[10].hex(), "K2": k2.hex()}


# ---------------------------------------------------------------- self-test
def self_test(verbose=True):
    ok = True
    # FIPS-197 Appendix C.1 (AES-128 block)
    rk = expand_key(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    c = aes_enc_block(rk, bytes.fromhex("00112233445566778899aabbccddeeff"))
    r = c.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a" and \
        aes_dec_block(rk, c).hex() == "00112233445566778899aabbccddeeff"
    ok &= r
    if verbose:
        print(f"FIPS-197 C.1 AES-128 enc/dec : {'PASS' if r else 'FAIL'}")
    # IEEE 1619-2007 Annex B vectors 1-3 (data unit sequence number as tweak input)
    vecs = [
        ("00" * 16 + "00" * 16, 0, "00" * 32,
         "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"),
        ("11" * 16 + "22" * 16, 0x3333333333, "44" * 32,
         "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0"),
        ("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" + "22" * 16, 0x3333333333, "44" * 32,
         "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89"),
    ]
    for n, (k, i, p, e) in enumerate(vecs, 1):
        k, p = bytes.fromhex(k), bytes.fromhex(p)
        c = xts_encrypt(k, i, p)
        r = c.hex() == e and xts_decrypt(k, i, c) == p
        ok &= r
        if verbose:
            print(f"IEEE 1619 vector {n} enc/dec   : {'PASS' if r else 'FAIL'}")
    # engine rule: K1 == K2 rejected in strict mode
    try:
        xts_encrypt(bytes(32), 0, bytes(64), strict=True)
        r = False
    except ValueError:
        r = True
    ok &= r
    if verbose:
        print(f"K1 == K2 rejected (strict)    : {'PASS' if r else 'FAIL'}")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if self_test() else 1)
