#!/usr/bin/env python3
"""score_task with an exclusive file lock around results.json read-modify-write
(fixes the concurrent-write corruption that hit at 10 workers)."""
import fcntl
import json
import os
import sys

sys.path.insert(0, "/home/naco/work/cybergym-agent")

tid = sys.argv[1]
out_dir = sys.argv[2]
stage = sys.argv[3] if len(sys.argv) > 3 else "pass1"
tdir = sys.argv[4] if len(sys.argv) > 4 else f"/data/cybergym/fullrun/tasks/{tid.replace(':', '_')}"

ws = os.environ.get("CG_WS_OVERRIDE") or f"/data/cybergym/agent-ws/{tid.replace(':', '_')}"
checks = 0
try:
    checks = int(open(f"{ws}/.checks").read())
except Exception:
    pass

success = False
try:
    setenv = open("/home/naco/work/cybergym/.env").read()
    key = [l.split("=", 1)[1].strip() for l in setenv.splitlines()
           if l.startswith("CYBERGYM_API_KEY=")][0]
    from plugins.cybergym_runner import CyberGymRunner
    runner = CyberGymRunner("http://172.17.0.1:8666", tdir, api_key=key)
    recs = runner.query_poc(original_task_id=tid)
    success = CyberGymRunner.official_success(recs)
except Exception:
    success = False

rp = f"{out_dir}/results.json"
lf = f"{out_dir}/results.lock"
lock = open(lf, "w")
fcntl.flock(lock, fcntl.LOCK_EX)
try:
    rows = []
    if os.path.exists(rp):
        try:
            rows = json.load(open(rp))
        except Exception:
            rows = []
    old = [r for r in rows if r["task_id"] == tid]
    row = {"task_id": tid, "official_success": success, "checks_used": checks,
           "stages": {}}
    if old:
        row["stages"].update(old[-1].get("stages", {}))
        row["second_pass"] = old[-1].get("second_pass") or stage == "pass2"
        row["retried"] = old[-1].get("retried") or stage == "retry"
    else:
        row["second_pass"] = stage == "pass2"
        row["retried"] = stage == "retry"
    row["stages"][stage] = success
    rows = [r for r in rows if r["task_id"] != tid]
    rows.append(row)
    tmp = rp + ".tmp"
    json.dump(rows, open(tmp, "w"), ensure_ascii=False, indent=2)
    os.replace(tmp, rp)
finally:
    fcntl.flock(lock, fcntl.LOCK_UN)
print(f"[score:{stage}] {tid}: success={success} checks={checks}")
