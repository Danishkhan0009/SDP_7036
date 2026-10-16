# Cross-check golden_kw against OpenSSL (via 'cryptography'): AES-KW, AES-CMAC, SP 800-108 KBKDF-CMAC.
import os, sys
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFCMAC, Mode, CounterLocation
from golden_kw import kw_wrap, kw_unwrap, cmac, derive_kek, LABEL
N = 1000; bad = {"kw": 0, "cmac": 0, "kdf": 0}
for _ in range(N):
    kek, data = os.urandom(16), os.urandom(32)          # D10: 256-bit K1||K2 under 128-bit KEK
    c = kw_wrap(kek, data)
    if c != aes_key_wrap(kek, data) or kw_unwrap(kek, c) != aes_key_unwrap(kek, c): bad["kw"] += 1
    m = os.urandom(os.urandom(1)[0] % 80); h = CMAC(algorithms.AES(kek)); h.update(m)
    if cmac(kek, m) != h.finalize(): bad["cmac"] += 1
    root, ep, sl = os.urandom(16), int.from_bytes(os.urandom(4), "big"), os.urandom(1)[0] % 4
    ref = KBKDFCMAC(algorithm=algorithms.AES, mode=Mode.CounterMode, length=16, rlen=4, llen=4,
                    location=CounterLocation.BeforeFixed, label=LABEL,
                    context=ep.to_bytes(4, "big") + bytes([sl]), fixed=None).derive(root)
    if derive_kek(root, ep, sl) != ref: bad["kdf"] += 1
for k, v in bad.items(): print(f"OpenSSL cross-check {k:<5} x{N}: {'PASS' if v == 0 else f'FAIL ({v})'}")
sys.exit(1 if any(bad.values()) else 0)
