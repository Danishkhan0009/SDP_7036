#!/usr/bin/env python3
"""Full-block vectors for the round-stage TB: key, pt, ct (golden AES-128). Byte k -> bits [8k+7:8k]."""
import os, sys, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "golden"))
from golden_xts import expand_key, aes_enc_block
rng = random.Random(6)
le = lambda b: int.from_bytes(b, "little")
rows = []
cases = [(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), bytes.fromhex("00112233445566778899aabbccddeeff"))]
cases += [(bytes(16), bytes(16)), (b"\xff" * 16, b"\xff" * 16)]
cases += [(bytes(rng.getrandbits(8) for _ in range(16)), bytes(rng.getrandbits(8) for _ in range(16))) for _ in range(300)]
for k, p in cases:
    rk = expand_key(k)
    rows.append(f"{le(k):032x}{le(rk[10]):032x}{le(p):032x}{le(aes_enc_block(rk, p)):032x}")
open(os.path.join(os.path.dirname(__file__), "..", "tb", "aes_blocks.hex"), "w").write("\n".join(rows) + "\n")
print(len(rows), "block vectors")
