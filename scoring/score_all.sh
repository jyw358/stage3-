#!/bin/bash
# score_all.sh: HOST-SIDE scoring. Fills official_success for every row of a
# results.json produced by run_agent_task.sh (which can no longer score, because
# POST /query-poc is a private route and the agent side must not hold the key).
#
# Runs as root. Usage:
#   /root/score_all.sh <out_root> [<task_base>]
#     <out_root>   dir containing results.json (e.g. /data/cybergym/stage3/r_engineer/out)
#     <task_base>  dir of prepared task dirs   (default: /data/cybergym/stage3/r_engineer/tasks)
set -u
OUT="${1:?usage: score_all.sh <out_root> [<task_base>]}"
TASKBASE="${2:-/data/cybergym/stage3/r_engineer/tasks}"
set -a; . /root/.cybergym_env; set +a

CG_OUT="$OUT" CG_TASKBASE="$TASKBASE" python3 - <<'PYEOF'
import json, os, sys
sys.path.insert(0, "/home/naco/work/cybergym-agent")
from plugins.cybergym_runner import CyberGymRunner

out = os.environ["CG_OUT"]
base = os.environ["CG_TASKBASE"]
rp = os.path.join(out, "results.json")
if not os.path.exists(rp):
    raise SystemExit("no results.json in %s" % out)
rows = json.load(open(rp))
key = os.environ["CYBERGYM_API_KEY"]
ok = 0
for row in rows:
    tid = row["task_id"]
    tdir = os.path.join(base, tid.replace(":", "_"))
    if not os.path.exists(os.path.join(tdir, "submit.sh")):
        row["score_error"] = "no submit.sh in %s" % tdir
        continue
    try:
        r = CyberGymRunner("http://172.17.0.1:8666", tdir, api_key=key)
        recs = r.query_poc(original_task_id=tid)
        row["official_success"] = CyberGymRunner.official_success(recs)
        row["pocs_submitted"] = len(recs)
        row["scored"] = True
        ok += 1
    except Exception as e:
        row["score_error"] = str(e)
json.dump(rows, open(rp, "w"), ensure_ascii=False, indent=2)
print("[scored] %d/%d rows in %s" % (ok, len(rows), rp))
PYEOF
