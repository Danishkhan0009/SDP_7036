#!/bin/bash
# run_fmax.sh - Task 6 fmax probe: 4 configs x 2 periods on GPDK045 slow corner, then summary.
# Run from the fmax/ folder on cadence47:  source <your env.sh>; ./syn/run_fmax.sh
set -u
: "${LIB_DIR:?set LIB_DIR to the gsclib045 timing folder (SYNC from your lib_setup.tcl)}"
: "${LIB_FILE:=slow_vdd1v0_basicCells.lib}"          # SYNC: your slow-corner std-cell .lib
[ -f "$LIB_DIR/$LIB_FILE" ] || { echo "PREFLIGHT FAIL: $LIB_DIR/$LIB_FILE not found"; exit 1; }
command -v genus >/dev/null || { echo "PREFLIGHT FAIL: genus not on PATH (source env.sh)"; exit 1; }
mkdir -p out logs
export LIB_DIR LIB_FILE
for TOP in probe_enc_lut probe_enc_tower probe_encdec_lut probe_encdec_tower; do
  for PERIOD_NS in 1.667 1.25; do
    export TOP PERIOD_NS
    echo "== $TOP @ $PERIOD_NS ns"
    genus -batch -no_gui -files syn/genus_one.tcl -log logs/genus_${TOP}_${PERIOD_NS} >/dev/null 2>&1
    grep -q "FMAX_DONE" logs/genus_${TOP}_${PERIOD_NS}.log* 2>/dev/null \
      && echo "   done" || echo "   FAILED - see logs/genus_${TOP}_${PERIOD_NS}.log"
  done
done
python3 syn/parse_fmax.py out | tee logs/fmax_summary.txt
