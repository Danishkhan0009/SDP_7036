# Cross-check golden_xts against OpenSSL (via 'cryptography') on 64 B lines, random keys/addresses.
import os, random, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from golden_xts import xts_encrypt, xts_decrypt, key_slot
random.seed(1619); N = 2000; bad = 0
for n in range(N):
    while True:
        key = os.urandom(32)
        if key[:16] != key[16:]: break
    addr = random.getrandbits(28)           # 28-bit line address (Spec 1.4 default)
    pt = os.urandom(64)                     # one 64 B line = 4 blocks
    tw = addr.to_bytes(16, "little")
    e = Cipher(algorithms.AES(key), modes.XTS(tw)).encryptor()
    ref = e.update(pt) + e.finalize()
    ct = xts_encrypt(key, addr, pt, strict=True)
    if ct != ref or xts_decrypt(key, addr, ct, strict=True) != pt: bad += 1
print(f"OpenSSL cross-check, {N} x 64 B lines, random addr: {'PASS' if bad == 0 else f'FAIL ({bad})'}")
tr = []; k = bytes(range(32)); xts_encrypt(k, 1, bytes(64), trace=tr)
print("trace addr=1, block 0 tweak T0 =", tr[0]["T"]); print("key slot example:", key_slot(k))
sys.exit(1 if bad else 0)
