#!/bin/bash
# repair_run.sh 2026-10-28: auditor no-output repair (O v2 list), mirrors stage3_waves.sh auditor slice
set -u
P=/data/cybergym/stage3
echo "REPAIR-START $(date -u +%FT%TZ) queue=13" >> "$P/waves.log"
S2_OUT="$P/r_auditor" S2_WS="$P/r_auditor-ws" S2_VARIANT=auditor S2_QUEUE="$P/repair_queue.json" \
  S2_STAGE_TAG=auditor S2_PAR=6 S2_KB_DIR="$P/kb_intel" \
  bash /home/naco/work/cybergym-agent/scripts/stage2.sh >> "$P/driver_repair.log" 2>&1
rm -f "$P/r_auditor/queue.json"
echo "REPAIR-COMPLETE $(date -u +%FT%TZ)" >> "$P/waves.log"
