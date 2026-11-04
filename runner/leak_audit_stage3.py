#!/usr/bin/env python3
"""Stage3 cross-workspace leakage scan v2 (2026-10-09).
v2 vs v1: adds relative-path sibling references (../arvo_X, and
r_engineer-ws/X without the absolute prefix) and sibling session-trajectory
reads (~/.claude/projects/-data-...-ws-<other>). KB reference-intel.md is
legal. Appends JSONL hits to /data/cybergym/stage3/leak_audit.log.
kind: sibling=abs path, rel=relative path, proj=sibling trajectory dir,
oldws=protected-area reference.
v3 10-09: OLD extended with agent-tasks|kb|quarantine_tmp|[a-z0-9-]+-ws to cover
historical ws blind spots (ab*/wave*/agent-ws/canary/cleanpilot); mission-text
backtick forms lack the /data/cybergym/ prefix so no per-session false noise;
cybergym-server-data intentionally excluded (sanctioned read-only task mounts)."""
import glob, os, re, json, time
PROJ = os.path.expanduser("~/.claude/projects")
SIB = re.compile(r"/data/cybergym/stage3/r_[a-z]+-ws/([A-Za-z0-9_.\-]+)")
OLD = re.compile(r"/data/cybergym/(stage1[^3]|stage2|server_poc|agent-tasks|kb|quarantine_tmp|[a-z0-9-]+-ws)")
ABS = re.compile(r"/data/cybergym/stage3/r_[a-z]+-ws/[A-Za-z0-9_.\-]+")
REL1 = re.compile(r"\.\./((?:arvo|oss-fuzz)[-_]\d+)")
REL2 = re.compile(r"r_[a-z]+-ws/((?:arvo|oss-fuzz)[-_]\d+)")
PRJ = re.compile(r"\.claude/projects/(-data-cybergym-stage3-r-[a-z]+-ws-[A-Za-z0-9_.\-]+)")
OUT = "/data/cybergym/stage3/leak_audit.log"

def sib_ok(mn, own):
    mn = mn.replace("-", "_").rstrip(".")
    return mn == own or mn.startswith(own + "_") or own.startswith(mn + "_")

hits = []
for d in glob.glob(PROJ + "/-data-cybergym-stage3-r-*-ws-*"):
    own = d.split("ws-", 1)[1].replace("-", "_")
    for f in glob.glob(d + "/*.jsonl"):
        try:
            txt = open(f, errors="ignore").read()
        except Exception:
            continue
        for m in set(SIB.findall(txt)):
            if not sib_ok(m, own):
                hits.append({"kind": "sibling", "own": own, "other": m, "sess": os.path.basename(f)})
        rest = ABS.sub(" ", txt)
        for m in set(REL1.findall(rest)) | set(REL2.findall(rest)):
            if not sib_ok(m, own):
                hits.append({"kind": "rel", "own": own, "other": m, "sess": os.path.basename(f)})
        for m in set(PRJ.findall(txt)):
            task = m.rsplit("ws-", 1)[1].replace("-", "_")
            if not sib_ok(task, own):
                hits.append({"kind": "proj", "own": own, "other": m, "sess": os.path.basename(f)})
        if OLD.search(txt):
            hits.append({"kind": "oldws", "own": own, "sess": os.path.basename(f)})
with open(OUT, "a") as fh:
    for h in hits:
        h["ts"] = time.strftime("%FT%TZ", time.gmtime())
        fh.write(json.dumps(h) + "\n")
print("scanned stage3 sessions; hits:", len(hits))
for h in hits[:25]:
    print(h)
