#!/usr/bin/env python3
"""check_vectors.py - read the .hex files back (as the testbench would) and verify every record
against OpenSSL via 'cryptography', independent of the golden model. Catches packing/byte-order bugs."""
import sys, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, InvalidUnwrap
from gen_vectors import LAYOUTS, field_ranges, width
from golden_xts import expand_key   # only for RK10 (OpenSSL does not expose round keys)

def records(path, layout):
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("//"): continue
        assert len(line) == width(layout) // 4, (path, len(line))
        v = int(line, 16); f = {}
        for name, hi, lo, kind in field_ranges(layout):
            x = (v >> lo) & ((1 << (hi - lo + 1)) - 1)
            f[name] = x.to_bytes((hi - lo + 1) // 8, "little") if kind == "b" else x
        yield f

def ossl_xts(key, addr, data, dec):
    c = Cipher(algorithms.AES(key), modes.XTS(addr.to_bytes(16, "little")))
    o = c.decryptor() if dec else c.encryptor()
    return o.update(data) + o.finalize()

d = sys.argv[1]; bad = 0
for fn in ("xts_directed.hex", "xts_random.hex"):
    n = e = 0
    for r in records(os.path.join(d, fn), "XTS"):
        n += 1; dec = (r["CTRL"] >> 2) & 1
        if ossl_xts(r["K1"] + r["K2"], r["ADDR"], r["DIN"], dec) != r["DOUT"]: e += 1
    print(f"{fn:<18} {n:>5} records vs OpenSSL : {'PASS' if e == 0 else f'FAIL {e}'}"); bad += e
n = e = 0
for r in records(os.path.join(d, "keyslot.hex"), "KEYSLOT"):
    n += 1; e += expand_key(r["K1"])[10] != r["RK10"]
print(f"{'keyslot.hex':<18} {n:>5} records RK10      : {'PASS' if e == 0 else f'FAIL {e}'}"); bad += e
n = e = 0
for r in records(os.path.join(d, "kw_standby.hex"), "KW"):
    n += 1
    try: k = aes_key_unwrap(r["KEK"], r["BLOB"]); ok = 1
    except InvalidUnwrap: k, ok = bytes(32), 0
    e += (ok != r["OK"]) or (ok and k != r["KEYS"])
print(f"{'kw_standby.hex':<18} {n:>5} records vs OpenSSL : {'PASS' if e == 0 else f'FAIL {e}'}"); bad += e
sys.exit(1 if bad else 0)
