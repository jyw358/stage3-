#!/bin/bash
# run_full_task.sh v3: adds the global window-budget gate before EVERY session
# launch. Over cap -> sleep until the 5h window rolls or a slot frees.
set -u
TID="$1"
WS="/data/cybergym/agent-ws/${TID//:/_}"
TDIR="/data/cybergym/fullrun/tasks/${TID//:/_}"
[ -f "$TDIR/submit.sh" ] || TDIR="/data/cybergym/fullstack-200/tasks/${TID//:/_}"
OUT=/data/cybergym/fullrun
AG=/home/naco/work/cybergym-agent
[ -f "$TDIR/submit.sh" ] || { echo "skip $TID"; exit 0; }
python3 "$AG/scripts/make_agent_ws.py" --task-dir "$TDIR" --task-id "$TID" --ws-root /data/cybergym/agent-ws >/dev/null || exit 2

wait_budget() {
  while true; do
    python3 "$AG/scripts/window_budget.py" check >/dev/null 2>&1 && return 0
    echo "=== $TID window-budget full, sleeping 300s ==="
    sleep 300
  done
}

run_session() {  # $1=prompt-file  $2=max-turns  $3=timeout  $4=tag
  wait_budget
  cat /data/cybergym/glm_active > "$OUT/${TID//:/_}.$4.key" 2>/dev/null || echo secondary > "$OUT/${TID//:/_}.$4.key"
  timeout "$3" /home/naco/bin/agcli -p "$(cat "$1")" \
      --max-turns "$2" --permission-mode bypassPermissions \
      --output-format json > "$OUT/${TID//:/_}.$4.json" 2>> "$OUT/${TID//:/_}.err"
}

score() { python3 "$AG/scripts/score_task.py" "$TID" "$OUT" "$1" "$TDIR" >/dev/null; }
state() { python3 -c "import json;rows=json.load(open('$OUT/results.json'));r=[x for x in rows if x['task_id']=='$TID'][-1];print('1' if r['official_success'] else '0')"; }

cd "$WS" || exit 0
set -a; . /home/naco/work/cybergym/.env; set +a
export CG_TASK_DIR="$TDIR" CG_TASK_ID="$TID" CG_SERVER="http://172.17.0.1:8666"

echo "=== $TID pass1 $(date +%m%d-%H:%M) ==="
run_session "$AG/scripts/agent_mission.txt" 45 2400 pass1
score pass1
[ "$(state)" = "1" ] && { echo "=== $TID solved@pass1 ==="; exit 0; }

c=$(cat "$WS/.checks" 2>/dev/null || echo 0)
if [ "$c" -eq 0 ] && [ ! -f "$WS/SOLUTION.md" ]; then
  echo "=== $TID pass2 $(date +%m%d-%H:%M) ==="
  rm -f "$WS/.gate_blocks"
  run_session "$AG/scripts/mission_pass2.txt" 25 1500 pass2
  score pass2
  [ "$(state)" = "1" ] && { echo "=== $TID solved@pass2 ==="; exit 0; }
fi

for r in 1 2; do
  if [ "$(state)" = "0" ] && { [ -f "$WS/SOLUTION.md" ] || [ "$(cat "$WS/.checks" 2>/dev/null || echo 0)" -gt 0 ]; }; then
    echo "=== $TID retry$r $(date +%m%d-%H:%M) ==="
    rm -f "$WS/.gate_blocks"
    python3 "$AG/scripts/gen_tried_paths.py" "$WS" "$OUT" >/dev/null 2>&1 || true
    if [ "$r" = "1" ]; then
      run_session "$AG/scripts/mission_retry.txt" 35 2100 retry1
    else
      run_session "$AG/scripts/mission_retry2.txt" 35 2100 retry2
    fi
    score retry$r
    [ "$(state)" = "1" ] && { echo "=== $TID solved@retry$r ==="; exit 0; }
  fi
done
echo "=== $TID done-unsolved ==="
