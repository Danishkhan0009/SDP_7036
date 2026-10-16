#!/usr/bin/env python3
"""parse_fmax.py - turn Genus reports into the Task 6 decision table.
stage delay d = period - slack; fmax = 1/d. Decision rule (Spec Section 4):
  synthesis-only d <= 1.33 ns  (1.667 ns / 1.25 margin for wires, CTS skew, setup) -> DDR5-4800
  else d <= 2.0 ns (2.5 / 1.25)                                                       -> DDR5-3200
If a regex finds nothing, the raw lines are printed: fix the pattern once (SYNC) and rerun."""
import glob, os, re, sys
d = sys.argv[1] if len(sys.argv) > 1 else "out"
SLACK = [r"Slack\s*:?=\s*(-?[\d.]+)", r"Timing slack\s*:\s*(-?[\d.]+)\s*ps",
         r"Path 1:\s*(?:MET|VIOLATED)\s*\((-?[\d.]+)\s*ps\)"]
rows = []
for t in sorted(glob.glob(os.path.join(d, "*_timing.rpt"))):
    top, per = re.match(r".*/(probe_\w+?)_([\d.]+)_timing\.rpt", t).groups()
    txt = open(t).read()
    slack = next((float(m.group(1)) for p in SLACK for m in [re.search(p, txt)] if m), None)
    area = None
    a = os.path.join(d, f"{top}_{per}_area.rpt")
    if os.path.exists(a):
        for line in open(a):
            if line.strip().startswith(top):
                nums = re.findall(r"[\d.]+", line.split(top, 1)[1])
                if len(nums) >= 2: area = float(nums[1])          # cell area (SYNC: check column)
    if slack is None:
        print(f"[parse] no slack found in {t}; last lines:\n" + "".join(txt.splitlines(True)[-15:]))
        continue
    dly = float(per) - slack / 1000.0                              # Genus reports ps
    rows.append((top, float(per), slack, dly, 1000.0 / dly, area))
print(f"{'config':<20}{'period ns':>10}{'slack ps':>10}{'stage ns':>10}{'fmax MHz':>10}{'cell area um2':>15}  verdict")
best = {}
for top, per, sl, dly, f, ar in rows:
    v = "4800 OK" if dly <= 1.333 else ("3200 OK" if dly <= 2.0 else "too slow")
    print(f"{top:<20}{per:>10.3f}{sl:>10.0f}{dly:>10.3f}{f:>10.0f}{(ar or 0):>15.0f}  {v}")
    if top not in best or dly < best[top][0]: best[top] = (dly, ar)
print("\nBest stage delay per config (use this row for the decision):")
for top, (dly, ar) in best.items():
    print(f"  {top:<20} {dly:.3f} ns  ({1000/dly:.0f} MHz)  area {ar}")
