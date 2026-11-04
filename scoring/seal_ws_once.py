#!/usr/bin/env python3
"""Seal completed stage3 workspaces (phase-1: ws only, NOT ~/.claude/projects).
Seal condition (all required): task has a results.json row; not named in
tainted.txt (needs rerun); not in current q_slice.json / r_*/queue.json;
no file inside the ws tree modified in the last 600s (worker tail + watcher
vaulting happen within seconds of the results row; 600s is triple margin).
Seal = chmod 000 -> chown root:root -> chmod 700 on the TOP dir only (zero
window where any non-root uid can traverse; root stays unaffected so
main_watcher_v2 vaulting and forensics keep working).
Usage: seal_ws_once.py                 -> seal pass
       seal_ws_once.py unseal <task>... -> restore for repair/rerun"""
import json, os, pwd, re, stat, sys, time
P = "/data/cybergym/stage3"
VARS = ("r_engineer", "r_auditor", "r_ctf")
AGE = 600

def log(m):
    with open(P + "/seal_ws.log", "a") as fh:
        fh.write(time.strftime("%FT%TZ ") + m + "\n")

def norm(t):
    return t.replace(":", "_")

def load_done():
    done = set()
    for v in VARS:
        try:
            for r in json.load(open(P + "/" + v + "/results.json")):
                done.add(norm(r["task_id"]))
        except Exception:
            pass
    return done

def load_tainted():
    # machine-readable id list takes precedence; tainted.txt kept as fallback/documentation
    for src in (P + "/tainted_ids.txt", P + "/tainted.txt"):
        try:
            txt = open(src, errors="ignore").read()
        except Exception:
            continue
        return {norm(t) for t in re.findall(r"(?:arvo|oss-fuzz)[:_]\d+", txt)}
    return set()

def load_active():
    act = set()
    srcs = [P + "/q_slice.json"] + [P + "/" + v + "/queue.json" for v in VARS]
    for f in srcs:
        try:
            for t in json.load(open(f)):
                act.add(norm(t if isinstance(t, str) else t.get("task_id", "")))
        except Exception:
            pass
    return act

def newest_mtime(path):
    m = 0.0
    for root, dirs, files in os.walk(path):
        try:
            m = max(m, os.path.getmtime(root))
        except OSError:
            pass
        for f in files:
            try:
                m = max(m, os.path.getmtime(os.path.join(root, f)))
            except OSError:
                pass
    return m

def is_task(n):
    return re.fullmatch(r"(?:arvo|oss-fuzz)_\d+", n) is not None

def seal():
    done, tainted, act = load_done(), load_tainted(), load_active()
    sealed = kept = 0
    now = time.time()
    for v in VARS:
        wsd = P + "/" + v + "-ws"
        if not os.path.isdir(wsd):
            continue
        for u in list(os.listdir(wsd)):
            path = os.path.join(wsd, u)
            try:
                if not is_task(u) or not os.path.isdir(path) or os.path.islink(path):
                    continue
                if os.stat(path).st_uid == 0:
                    continue
                if u not in done or u in tainted or u in act:
                    kept += 1
                    continue
                if now - newest_mtime(path) < AGE:
                    kept += 1
                    continue
                os.chmod(path, 0o000)
                os.chown(path, 0, 0)
                os.chmod(path, 0o700)
                log("sealed " + v + "-ws/" + u)
                sealed += 1
            except FileNotFoundError:
                continue
    log("pass done: sealed=%d kept-open=%d (done=%d tainted=%d active=%d)"
        % (sealed, kept, len(done), len(tainted), len(act)))

def unseal(names):
    for u in names:
        for v in VARS:
            path = P + "/" + v + "-ws/" + u
            if os.path.isdir(path) and not os.path.islink(path):
                os.chmod(path, 0o000)
                os.chown(path, pwd.getpwnam("naco").pw_uid, pwd.getpwnam("naco").pw_gid)
                os.chmod(path, 0o755)
                log("unsealed " + v + "-ws/" + u)

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "unseal":
        unseal(sys.argv[2:])
    else:
        seal()
