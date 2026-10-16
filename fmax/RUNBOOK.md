# Task 6 fmax probe - runbook

Put this folder in the repo as `fmax/`. All commands run from inside `fmax/`.

## Laptop (WSL), before the lab - 5 min
    make sim                      # Icarus, ~3 min: expect ROUND_TB PASS
    git add . && git commit -m "Task 6: AES round-stage probe RTL + TB" && git push

## cadence47 - day 1
    git pull
    source <your env.sh>          # licence + Cadence PATH, from flowcheck v4.0
    make sim SIM=xcelium          # expect ROUND_TB PASS in logs/round_xrun.log
    export LIB_DIR=<gsclib045 timing folder>        # SYNC: copy from your lib_setup.tcl
    export LIB_FILE=slow_vdd1v0_basicCells.lib      # SYNC: your slow-corner std-cell lib name
    export DH_CELLS=<path>/dh_cells.tcl             # optional: 62 double-height dont_use cells
    make fmax                     # 8 Genus runs (4 configs x 1.667/1.25 ns), then the summary table

## If something fails
- `PREFLIGHT FAIL` -> LIB_DIR / LIB_FILE / env.sh not set.
- A run says FAILED -> open logs/genus_<top>_<period>.log, search for "Error".
- Summary prints "[parse] no slack found" -> paste the printed report lines to Claude; fix the regex once.
- Area column empty or wrong -> check which column of report_area is cell area (SYNC in parse_fmax.py).

## What to bring back
logs/fmax_summary.txt and the 8 out/*_timing.rpt files. Commit them.

## Decision rule (Spec Section 4)
Synthesis-only stage delay d (best of the two periods) per config:
- d <= 1.33 ns for an enc+dec config  -> option A at DDR5-4800 (pick the smaller-area S-box style)
- only enc-only configs <= 1.33 ns   -> DDR5-3200 (option C), or option B if the guide insists on 4800
- nothing <= 2.0 ns                  -> stop and review the pipeline cut (S-box split across 2 stages)
The 1.25x margin covers wires, clock-tree skew and setup that synthesis does not see.
