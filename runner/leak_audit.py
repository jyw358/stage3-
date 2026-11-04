#!/usr/bin/env python3
"""Cross-workspace leakage audit for the stage1 clean retest.

Scans every stage1 session trajectory for tool_use commands that read,
grep, list or copy PRIOR-SOLUTION surfaces: historical *-ws workspaces,
server_poc, kb, quarantine_tmp, finalwave, submission_export, other
sessions' ~/.claude/projects dirs, and OTHER stage1-ws task dirs
(cross-task sibling reads). Outputs JSONL to /data/cybergym/stage1/leak_audit.log.

  python3 leak_audit.py [--since-tasks N]   # summary printed, detail in log
"""
import glob
import json
import os
import re
import sys

ST = "/data/cybergym/stage1"
SENSITIVE = re.compile(
    r"/data/cybergym/(cleanpilot-ws|agent-ws|wave\d[^ /\"]*-ws|ab\d[^ /\"]*-ws|ab-ws|canary-ws"
    r"|server_poc|pocserver-cleanrun|kb|quarantine_tmp|finalwave|submission_export|backup_server_poc)"
    r"(\.sh)?[/ \"']?"
    r"|~/\.claude/projects/-(?!data-cybergym-stage1-ws-)[a-z0-9-]+"
    r"|\.claude/projects/-data-cybergym-(?!stage1-ws-)[a-z0-9-]+", re.X)
STAGE1_SIBLING = re.compile(r"/data/cybergym/stage[12](?:/pilot/r_[a-z]+)?-ws/([A-Za-z0-9_.:-]+)")

# docker bypass: the daemon is root, so `-v <sensitive>:/x` ignores host perms
DOCKER_BYPASS = re.compile(
    r"docker\s+(run|create|exec|build)[^|;&]*"
    r"(-v\s+|--mount\s+[^ ]*source=|--volume\s+)"
    r"(/[\s:,]|/data([\s:]|$)|/data/cybergym/(server_poc|agent-ws|cleanpilot-ws|wave\d[^\s:]*-ws|ab\d[^\s:]*-ws|ab-ws|canary-ws|kb|quarantine_tmp|finalwave|submission_export)"
    r"|/root([\s:]|$)|/home/naco/\.claude)", re.X)


def audit():
    hits = {}
    projects = sorted(glob.glob(os.path.expanduser(
        "~/.claude/projects/-data-cybergym-stage1-ws-*")) +
        glob.glob(os.path.expanduser(
        "~/.claude/projects/-data-cybergym-stage2-*")))
    skip = set()
    try:
        skip = {l.strip() for l in open(f"{ST}/tainted_sessions.txt", errors="replace") if l.strip() and not l.startswith("#")}
    except Exception:
        pass
    for proj in projects:
        own = proj.rsplit("-ws-", 1)[-1].replace("_", "-")  # e.g. arvo-10628
        thits = []
        own_proj = proj
        for jl in glob.glob(proj + "/*.jsonl"):
            if os.path.basename(jl) in skip:
                continue
            for line in open(jl, encoding="utf-8", errors="replace"):
                if ("/data/cybergym/" not in line and ".claude/projects" not in line
                        and "docker " not in line):
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if ev.get("type") != "assistant":
                    continue
                for c in (ev.get("message") or {}).get("content") or []:
                    if not (isinstance(c, dict) and c.get("type") == "tool_use"):
                        continue
                    cmd = str((c.get("input") or {}).get("command", "")
                              ) + " " + str((c.get("input") or {}).get("file_path", "")
                              ) + " " + str((c.get("input") or {}).get("pattern", ""))
                    cmd_n = " ".join(cmd.split()).replace("~/.claude", os.path.expanduser("~/.claude"))
                    # own-project memory/tool-results reads are benign
                    if own_proj in cmd_n and "stage1-ws" not in own_proj:
                        continue
                    db = DOCKER_BYPASS.search(cmd_n)
                    if db:
                        thits.append({"tool": c.get("name"), "session": os.path.basename(jl),
                                      "match": "docker-bypass:" + db.group(0)[:60],
                                      "cmd": cmd[:160]})
                    if re.search(r"\b(ls|find|grep|rg)\b[^|;&]*stage1-ws/?([\s\"']|$)", cmd_n) \
                            and "/stage1-ws/" not in cmd_n:
                        thits.append({"tool": c.get("name"), "session": os.path.basename(jl),
                                      "match": "parent-list",
                                      "cmd": cmd[:120]})
                    m = SENSITIVE.search(cmd)
                    if m:
                        thits.append({"tool": c.get("name"), "session": os.path.basename(jl),
                                      "match": m.group(0)[:80],
                                      "cmd": cmd[:160]})
                        continue
                    for s in STAGE1_SIBLING.finditer(cmd):
                        if s.group(1).rstrip(":").replace("_", "-") != own:
                            thits.append({"tool": c.get("name"), "session": os.path.basename(jl),
                                          "match": "sibling:" + s.group(1),
                                          "cmd": cmd[:160]})
                            break
        if thits:
            hits[own] = thits
    with open(f"{ST}/leak_audit.log", "a") as f:
        for task, hs in hits.items():
            f.write(json.dumps({"task": task, "hits": len(hs),
                                "detail": hs[:10]}, ensure_ascii=False) + "\n")
    return hits


if __name__ == "__main__":
    h = audit()
    print(f"audited stage1 projects; tasks with leakage-pattern hits: {len(h)}")
    for t, hs in list(h.items())[:10]:
        print(f"  {t}: {len(hs)} hits, e.g. {hs[0]['match']} :: {hs[0]['cmd'][:80]}")
    print("full detail appended to /data/cybergym/stage1/leak_audit.log")
