#!/usr/bin/env python3
"""
gen_vectors.py - Task 4: export golden-model results as $readmemh files for the testbench.

Usage: python3 gen_vectors.py [outdir]      (default: ../vectors)

Single source of truth for record layouts: LAYOUTS below. The same table writes
  - the .hex files,
  - vec_layout.svh (SystemVerilog `defines for every field's [msb:lsb]),
  - vec_expect.svh (record counts + first/last record fields, for the loader self-check),
  - FORMAT.md and MANIFEST.txt.
Deterministic: fixed seed, no os.urandom -> same files, same SHA-256 every run.

Byte-order rule (Spec 2.2, FORMAT.md):
  byte strings (data, keys, tweaks, blobs, KEK, root): byte 0 -> field[7:0]  (little-byte)
  integers (addr, epoch, slot, dir, counters):         natural binary value
"""
import hashlib
import os
import random
import sys

from golden_xts import xts_encrypt, xts_decrypt, expand_key, aes_enc_block, mul_alpha, tweak_bytes
from golden_kw import derive_kek, kw_wrap, kw_unwrap

SEED = 20261016
ADDR_BITS = 28

# name -> list of (field, bits, kind) from MSB to LSB; kind 'b' = byte string, 'i' = integer
LAYOUTS = {
    "XTS": [("CTRL", 8, "i"), ("ADDR", 32, "i"), ("K1", 128, "b"), ("K2", 128, "b"),
            ("DIN", 512, "b"), ("DOUT", 512, "b")],
    "KEYSLOT": [("K1", 128, "b"), ("K2", 128, "b"), ("RK10", 128, "b")],
    "TRACE": [("REC", 16, "i"), ("J", 8, "i"), ("T", 128, "b"), ("BIN", 128, "b"),
              ("PRE", 128, "b"), ("AES", 128, "b"), ("BOUT", 128, "b")],
    "KW": [("TYPE", 8, "i"), ("OK", 8, "i"), ("SLOT", 8, "i"), ("EPOCH", 32, "i"),
           ("ROOT", 128, "b"), ("KEK", 128, "b"), ("KEYS", 256, "b"), ("RK10", 128, "b"),
           ("BLOB", 320, "b")],
}
CTRL_DOC = "CTRL = {5'b0, dir, slot[1:0]}; dir 0 = encrypt (write), 1 = decrypt (read)"
KW_DOC = ("TYPE 0 = wrap (in: ROOT, EPOCH, SLOT, KEYS; expect: KEK, BLOB). "
          "TYPE 1 = unwrap (in: ROOT, EPOCH, SLOT, BLOB; expect: OK, and if OK=1 KEYS + RK10, else zeros)")


def width(name):
    return sum(b for _, b, _ in LAYOUTS[name])


def pack(name, **f):
    v = 0
    for field, bits, kind in LAYOUTS[name]:
        x = f[field]
        if kind == "b":
            assert isinstance(x, (bytes, bytearray)) and len(x) * 8 == bits, (name, field)
            x = int.from_bytes(x, "little")  # byte 0 -> [7:0]
        assert 0 <= x < (1 << bits), (name, field, x)
        v = (v << bits) | x
    return f"{v:0{width(name) // 4}x}"


def field_ranges(name):
    out, hi = [], width(name) - 1
    for field, bits, kind in LAYOUTS[name]:
        out.append((field, hi, hi - bits + 1, kind))
        hi -= bits
    return out


class HexFile:
    def __init__(self, layout):
        self.layout, self.lines, self.n, self.first, self.last = layout, [], 0, None, None

    def add(self, label=None, **f):
        if label:
            self.lines.append(f"// [{self.n}] {label}")
        self.lines.append(pack(self.layout, **f))
        self.first = self.first or f
        self.last = f
        self.n += 1


# ---------------------------------------------------------------- XTS records
def xts_record(hf, tr, label, slot, addr, keypair, data, direction):
    k1, k2 = keypair
    key = k1 + k2
    trace = []
    if direction == 0:
        out = xts_encrypt(key, addr, data, strict=True, trace=trace)
    else:
        out = xts_decrypt(key, addr, data, strict=True, trace=trace)
    rec = hf.n
    hf.add(label, CTRL=(direction << 2) | slot, ADDR=addr, K1=k1, K2=k2, DIN=data, DOUT=out)
    if tr is not None:
        for t in trace:
            tr.add(None, REC=rec, J=t["j"], T=bytes.fromhex(t["T"]), BIN=bytes.fromhex(t["in"]),
                   PRE=bytes.fromhex(t["pre"]), AES=bytes.fromhex(t["aes"]), BOUT=bytes.fromhex(t["out"]))
    return out


def t0(k2, addr):
    return aes_enc_block(expand_key(k2), tweak_bytes(addr))


def carries(t):
    return t[15] >> 7  # bit 127 of the little-endian tweak value


def directed(rng, xd, tr):
    slots = [(bytes(rng.getrandbits(8) for _ in range(16)), bytes(rng.getrandbits(8) for _ in range(16)))
             for _ in range(4)]
    A = slots[0]
    rnd = lambda n: bytes(rng.getrandbits(8) for _ in range(n))
    amax = (1 << ADDR_BITS) - 1
    cases = [
        ("addr 0, all-zero data, slot 0", 0, 0, A, bytes(64)),
        ("max 28-bit addr, slot 0", 0, amax, A, rnd(64)),
        ("all-ones data, slot 0", 0, 0x123456, A, b"\xff" * 64),
        ("addr 1 (little-endian tweak check), slot 0", 0, 1, A, rnd(64)),
    ]
    for s in range(4):
        cases.append((f"same addr + data, slot {s}", s, 0x0ABCDE, slots[s], bytes(range(64))))
    # near-duplicate keys: K2 = K1 with one bit flipped (legal, K1 != K2)
    k1 = rnd(16)
    nd = (k1, bytes([k1[0] ^ 1]) + k1[1:])
    cases.append(("near-duplicate keys (K2 = K1 ^ 1 bit)", 1, 0x55AA55, nd, rnd(64)))
    # alpha carry path: find addresses where T0 does / does not set bit 127
    a_c = next(a for a in range(1, 1 << 16) if carries(t0(A[1], a)))
    cases.append(("alpha carry on T0 -> T1 (0x87 path)", 0, a_c, A, rnd(64)))
    a_n = next(a for a in range(1, 1 << 16)
               if not any(carries(t) for t in _tweaks(A[1], a)[:3]))
    cases.append(("no alpha carry on T0..T2", 0, a_n, A, rnd(64)))
    # each case in both directions: encrypt, then decrypt of the produced ciphertext
    for label, s, a, kp, pt in cases:
        ct = xts_record(xd, tr, "ENC " + label, s, a, kp, pt, 0)
        xts_record(xd, tr, "DEC " + label, s, a, kp, ct, 1)
    # back-to-back slot switching and direction switching on one address
    pt = rnd(64)
    cts = {}
    for n, s in enumerate([0, 1, 0, 1, 2, 3, 2, 3]):
        cts[s] = xts_record(xd, tr, f"key-switch seq {n}: ENC slot {s}", s, 0x7777, slots[s], pt, 0)
    for n, s in enumerate([3, 0, 2, 1]):
        xts_record(xd, tr, f"key-switch seq: DEC slot {s}", s, 0x7777, slots[s], cts[s], 1)
    return slots


def _tweaks(k2, a):
    t = [t0(k2, a)]
    for _ in range(3):
        t.append(mul_alpha(t[-1]))
    return t


def random_lines(rng, xr, tr, n_lines=1000, rotate=100):
    rnd = lambda m: bytes(rng.getrandbits(8) for _ in range(m))

    def newkey():
        while True:
            k = (rnd(16), rnd(16))
            if k[0] != k[1]:
                return k

    slots = [newkey() for _ in range(4)]
    written = []  # (slot, addr, keypair, ct) available for later reads
    for i in range(n_lines):
        if i and i % rotate == 0:  # rotate one slot's key; its old lines are dropped
            s = rng.randrange(4)
            slots[s] = newkey()
            written = [w for w in written if w[0] != s]
        s, a = rng.randrange(4), rng.getrandbits(ADDR_BITS)
        ct = xts_record(xr, tr if xr.n < 100 else None, None, s, a, slots[s], rnd(64), 0)
        written.append((s, a, slots[s], ct))
        # mixed traffic: about half the time, read back a random earlier line
        if rng.random() < 0.5 or i == n_lines - 1:
            s2, a2, kp2, ct2 = written[rng.randrange(len(written))]
            xts_record(xr, tr if xr.n < 100 else None, None, s2, a2, kp2, ct2, 1)
    # make sure every written line is read back at least once at the end? not needed:
    # each DEC record is checked against its own ENC through the golden model.


# ---------------------------------------------------------------- key slot + KW records
def keyslot_records(rng, ks, extra):
    rnd = lambda m: bytes(rng.getrandbits(8) for _ in range(m))
    fips = (bytes.fromhex("000102030405060708090a0b0c0d0e0f"), bytes.fromhex("101112131415161718191a1b1c1d1e1f"))
    for k1, k2 in [fips] + extra + [(rnd(16), rnd(16)) for _ in range(64)]:
        ks.add(None, K1=k1, K2=k2, RK10=expand_key(k1)[10])


def kw_records(rng, kw):
    rnd = lambda m: bytes(rng.getrandbits(8) for _ in range(m))
    z = dict(KEK=bytes(16), KEYS=bytes(32), RK10=bytes(16))
    root = rnd(16)
    epoch = 0
    for cycle in range(8):  # 8 standby cycles, all 4 slots each
        epoch += 1
        keys = [rnd(32) for _ in range(4)]
        blobs = []
        for s in range(4):
            kek = derive_kek(root, epoch, s)
            b = kw_wrap(kek, keys[s])
            blobs.append(b)
            kw.add(f"wrap   epoch {epoch} slot {s}", TYPE=0, OK=1, SLOT=s, EPOCH=epoch, ROOT=root,
                   KEK=kek, KEYS=keys[s], RK10=expand_key(keys[s][:16])[10], BLOB=b)
        for s in range(4):
            kek = derive_kek(root, epoch, s)
            kw.add(f"unwrap epoch {epoch} slot {s} OK", TYPE=1, OK=1, SLOT=s, EPOCH=epoch, ROOT=root,
                   KEK=kek, KEYS=keys[s], RK10=expand_key(keys[s][:16])[10], BLOB=blobs[s])
        if cycle == 0:
            prev = (epoch, blobs)
    # negative cases (expect OK = 0)
    e_old, b_old = prev
    neg = [("stale blob: epoch 1 blob, current epoch", epoch, 0, root, b_old[0]),
           ("blob of slot 1 presented as slot 0", e_old, 0, root, b_old[1]),
           ("wrong root", e_old, 0, rnd(16), b_old[0]),
           ("epoch + 1 (wrap/increment order bug)", e_old + 1, 0, root, b_old[0])]
    for bit in (0, 63, 64, 191, 319):
        bad = bytearray(b_old[0])
        bad[bit // 8] ^= 1 << (bit % 8)
        neg.append((f"blob bit {bit} flipped", e_old, 0, root, bytes(bad)))
    for label, e, s, r, b in neg:
        kek = derive_kek(r, e, s)
        assert kw_unwrap(kek, b) is None
        kw.add("unwrap " + label + " -> REJECT", TYPE=1, OK=0, SLOT=s, EPOCH=e, ROOT=r, BLOB=b,
               **dict(z, KEK=kek))


# ---------------------------------------------------------------- outputs
def write_svh(out, files):
    L = ["// AUTO-GENERATED by gen_vectors.py - do not edit. Field slices for $readmemh records.",
         "`ifndef VEC_LAYOUT_SVH", "`define VEC_LAYOUT_SVH"]
    for name in LAYOUTS:
        L.append(f"`define {name}_W {width(name)}")
        for field, hi, lo, _ in field_ranges(name):
            L.append(f"`define {name}_{field} {hi}:{lo}")
    L.append("`endif")
    open(os.path.join(out, "vec_layout.svh"), "w").write("\n".join(L) + "\n")

    E = ["// AUTO-GENERATED by gen_vectors.py - expected counts and first/last fields for tb_vec_load.",
         "`ifndef VEC_EXPECT_SVH", "`define VEC_EXPECT_SVH"]
    for fname, hf in files.items():
        tag = fname.split(".")[0].upper()
        E.append(f"`define N_{tag} {hf.n}")
        for which, rec in (("FIRST", hf.first), ("LAST", hf.last)):
            for field, hi, lo, kind in field_ranges(hf.layout):
                x = rec.get(field, 0)
                x = int.from_bytes(x, "little") if kind == "b" else x
                E.append(f"`define {tag}_{which}_{field} {hi - lo + 1}'h{x:x}")
    E.append("`endif")
    open(os.path.join(out, "vec_expect.svh"), "w").write("\n".join(E) + "\n")


def write_format(out):
    L = ["# Vector file format (auto-generated)", "",
         "One record per line, hex, MSB first, as `$readmemh` expects. `// [n] label` lines are comments.", "",
         "**Byte-order rule:** byte strings (data, keys, tweaks, KEK, root, blob) put byte 0 in field[7:0]. "
         "Integers (ADDR, EPOCH, SLOT, CTRL, REC, J) are plain binary values.", "",
         f"- {CTRL_DOC}", f"- {KW_DOC}", ""]
    for name in LAYOUTS:
        L += [f"## {name} ({width(name)} bits)", "", "| Field | Bits | Type |", "| --- | --- | --- |"]
        for field, hi, lo, kind in field_ranges(name):
            L.append(f"| {field} | [{hi}:{lo}] | {'byte string' if kind == 'b' else 'integer'} |")
        L.append("")
    open(os.path.join(out, "FORMAT.md"), "w").write("\n".join(L))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "vectors")
    os.makedirs(out, exist_ok=True)
    rng = random.Random(SEED)
    files = {"xts_directed.hex": HexFile("XTS"), "xts_random.hex": HexFile("XTS"),
             "xts_trace.hex": HexFile("TRACE"), "keyslot.hex": HexFile("KEYSLOT"),
             "kw_standby.hex": HexFile("KW")}
    tr = files["xts_trace.hex"]
    slots = directed(rng, files["xts_directed.hex"], tr)
    random_lines(rng, files["xts_random.hex"], tr)
    keyslot_records(rng, files["keyslot.hex"], slots)
    kw_records(rng, files["kw_standby.hex"])

    man = [f"gen_vectors.py seed={SEED}", ""]
    for fname, hf in files.items():
        data = "\n".join(hf.lines) + "\n"
        open(os.path.join(out, fname), "w").write(data)
        man.append(f"{fname:<18} {hf.layout:<8} {width(hf.layout):>5} bits  {hf.n:>5} records  "
                   f"sha256 {hashlib.sha256(data.encode()).hexdigest()[:16]}")
    write_svh(out, files)
    write_format(out)
    open(os.path.join(out, "MANIFEST.txt"), "w").write("\n".join(man) + "\n")
    print("\n".join(man))


if __name__ == "__main__":
    main()
