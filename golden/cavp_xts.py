#!/usr/bin/env python3
"""
cavp_xts.py - Run NIST CAVP XTSGenAES128.rsp vectors through golden_xts.py (Task 2.3-2.4).

Usage: python3 cavp_xts.py <XTSGenAES128.rsp> [more .rsp files] [--log out.log]

Handles both CAVP tweak formats:
  'i = <32 hex>'                 -> raw 16-byte tweak value
  'DataUnitSeqNumber = <decimal>' -> integer, little-endian (same path as a line address)
Records whose DataUnitLen is not a multiple of 128 need ciphertext stealing, which the
engine does not implement (Spec D2): they are counted as OUT_OF_SCOPE, not run.
"""
import sys
from golden_xts import xts_encrypt, xts_decrypt


def parse(path):
    recs, mode, cur = [], None, {}
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if line in ("[ENCRYPT]", "[DECRYPT]"):
                mode = line[1:-1]
                continue
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = (s.strip() for s in line.split("=", 1))
            if k == "COUNT":
                if cur:
                    recs.append(cur)
                cur = {"mode": mode, "COUNT": int(v)}
            else:
                cur[k] = v
    if cur:
        recs.append(cur)
    return recs


def run(path, log):
    recs = parse(path)
    res = {"PASS": 0, "FAIL": 0, "OUT_OF_SCOPE": 0}
    for r in recs:
        bits = int(r["DataUnitLen"])
        tag = f"{r['mode']} COUNT={r['COUNT']} len={bits}"
        if bits % 128:
            res["OUT_OF_SCOPE"] += 1
            log.write(f"OUT_OF_SCOPE {tag} (ciphertext stealing)\n")
            continue
        key = bytes.fromhex(r["Key"])
        i = bytes.fromhex(r["i"]) if "i" in r else int(r["DataUnitSeqNumber"])
        pt, ct = bytes.fromhex(r["PT"]), bytes.fromhex(r["CT"])
        got = xts_encrypt(key, i, pt) if r["mode"] == "ENCRYPT" else xts_decrypt(key, i, ct)
        want = ct if r["mode"] == "ENCRYPT" else pt
        ok = got == want
        res["PASS" if ok else "FAIL"] += 1
        log.write(f"{'PASS' if ok else 'FAIL'} {tag}" + ("" if ok else f" got={got.hex()} want={want.hex()}") + "\n")
    return len(recs), res


if __name__ == "__main__":
    args = sys.argv[1:]
    logp = "cavp_xts.log"
    if "--log" in args:
        n = args.index("--log")
        logp = args[n + 1]
        del args[n:n + 2]
    fail = 0
    with open(logp, "w") as log:
        for p in args:
            log.write(f"== {p}\n")
            n, res = run(p, log)
            fail += res["FAIL"]
            line = (f"{p.split('/')[-2] if '/' in p else p}: {n} records | in scope "
                    f"{res['PASS'] + res['FAIL']}: PASS {res['PASS']} FAIL {res['FAIL']} | "
                    f"out of scope (stealing) {res['OUT_OF_SCOPE']}")
            print(line)
            log.write(line + "\n")
    print(f"CAVP_XTS {'PASS' if fail == 0 else 'FAIL'}  (log: {logp})")
    sys.exit(1 if fail else 0)
