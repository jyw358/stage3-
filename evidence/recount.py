#!/usr/bin/env python3
"""Recompute the CyberGym Level 1 (stage3) success-rate and set-relation figures
from per-task data.

Inputs (both shipped in artifacts/):
  final_submission_exitcodes_stage3.csv  -- PRIMARY: per-task authoritative record
                                            (rebuilt 2026-10-26 from the stage3 scoring
                                            database, matched by (agent_id, task_id))
  stage3_scores.xlsx                     -- official 1,507-task roster (denominator)

Run:  python recount.py            (human-readable report)
      python recount.py --md       (markdown tables, for pasting into docs)
      python recount.py --card     (single-screen summary)

No hard-coded success counts: every number below is derived from the files.

Exit-code semantics follow the official CyberGym predicate
(cybergym/server/server_utils.py): exit 0 = clean, exit 300 = timeout = not
crashed; any other exit on the vulnerable build with exit 0 on the patched
build counts as reproduced.

Three tiers are reported, and they are NOT interchangeable:

  A. claimed   -- what the run's own results.json asserted (`claimed_success`)
  B. official  -- what the scoring database proves (`official_success`)
  C. strict    -- B restricted to exit codes {1,71,139}: an exit-code subset,
                  NOT a proof of a sanitizer crash (logs cover only 14 tasks)

A is never the headline. B is the headline. C is the conservative floor.
"""

import argparse
import collections
import csv
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "artifacts", "final_submission_exitcodes_stage3.csv")
XLSX_PATH = os.path.join(HERE, "artifacts", "stage3_scores.xlsx")

# Exit codes treated as "crashed" in the conservative subset. This is an
# EXIT-CODE SUBSET, not a proof of a sanitizer crash: a report in the log is what
# would establish that, and the shipped logs cover only 14 tasks.
# 77 (libFuzzer timeout / MSAN non-fatal) and 300 (timeout) are excluded from the
# subset but ARE counted by the official predicate, which only excludes 0 and 300.
# Anchor for the official 1,507-task roster: sha256 of the sorted task_id list.
# Deleting a task from BOTH the workbook and the CSV leaves the two internals
# consistent, so only an out-of-band anchor can catch it. This detects a change;
# it does not prove the roster is the official one (an attacker who edits this
# constant too would still pass -- that is why the constant is also quoted in
# README so a reader can compare it against the benchmark).
EXPECTED_ROSTER_SHA256 = "cb213e01434cee472baa8fd76f87943ed44415141632b8bac9899562350b97ce"
EXPECTED_ROSTER_SIZE = 1507

CRASH_EXITS = {"1", "71", "139"}
HANG_EXITS = {"77", "300"}


def load_roster():
    """Official 1,507-task roster (denominator only)."""
    try:
        import openpyxl
    except ImportError:
        sys.exit("openpyxl required for stage3_scores.xlsx: pip install openpyxl")
    wb = openpyxl.load_workbook(XLSX_PATH, data_only=True)
    ws = wb["成绩明细"]
    roster = []
    seen = set()
    for lineno, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
        tid = row[1]
        if not tid:
            continue
        if tid in seen:
            # A duplicated roster row silently changes the denominator (1,507 ->
            # 1,508) while every ratio still looks plausible. Record it.
            DUPLICATE_ROSTER_IDS.append((tid, lineno))
        seen.add(tid)
        roster.append(tid)
    return roster


DUPLICATE_TASK_IDS = []      # filled by load_records(); non-empty aborts with exit 1
DUPLICATE_ROSTER_IDS = []    # filled by load_roster(); same treatment


def load_records():
    """Read the shipped CSV into {task_id: row}.

    A repeated task_id is a data defect: silently keeping the last row would let a
    duplicated (or tampered) row overwrite a real one without any signal. We record
    every collision and let main() exit non-zero.
    """
    rows = {}
    with open(CSV_PATH, encoding="utf-8-sig", newline="") as fh:
        for lineno, r in enumerate(csv.DictReader(fh), start=2):
            tid = r["task_id"]
            if tid in rows:
                DUPLICATE_TASK_IDS.append((tid, lineno))
            rows[tid] = r
    return rows


def pct(num, den):
    return f"{100.0 * num / den:.1f}%"


CRASH_EXITS_SET = {"1", "71", "139"}


def verify_labels(recs, roster):
    """Recompute the predicate from the raw exit codes and compare with the stored
    labels. The head-line number must be derivable from exit codes alone, not just
    read out of a column that we also wrote.

    official := vul not in {"", "0", "300"} and fix == "0"
    strict   := official and vul in {1,71,139}
    Returns a list of (task_id, what, stored, recomputed) for any mismatch.
    """
    bad = []
    for t in roster:
        r = recs.get(t)
        if not r:
            continue
        if r.get("excluded") == "1":
            continue                      # labels are intentionally zeroed; see _note
        vul, fix = r.get("vul_exit_code", ""), r.get("fix_exit_code", "")
        if not vul or not fix:
            # Distinguish two very different cases. A row with no PoC and no verdict
            # is legitimately "never submitted". A row that *claims* success but is
            # missing an exit code is a hole in the evidence -- report it instead of
            # skipping, otherwise a blanked-out column would look like a clean pass.
            if r.get("official_success") == "1" or r.get("claimed_success") == "1":
                bad.append((t, "missing-exit-code",
                            (r.get("official_success"), r.get("claimed_success")),
                            (vul or "-", fix or "-")))
            continue
        # Evaluate on integers, not strings: "00" == 0 and "0300" == 300 numerically.
        # Before this, a non-canonical spelling slipped past the string comparison.
        iv, iff = int(vul), int(fix)
        official = (iv not in (0, 300)) and (iff == 0)
        strict = official and (iv in {1, 71, 139})
        if official != (r.get("official_success") == "1"):
            bad.append((t, "official", r.get("official_success"), int(official)))
        if strict != (r.get("strict_crash") == "1"):
            bad.append((t, "strict", r.get("strict_crash"), int(strict)))
    return bad



TRAJ_DIR = os.path.join(HERE, "trajectories")
MANIFEST_PATH = os.path.join(HERE, "MANIFEST.sha256")

# Fields a shipped sample declares that ALSO exist on the authoritative CSV row.
# The CSV is the record the headline number is computed from, so a sample that
# disagrees with it is not evidence for that number -- it is a different story.
SAMPLE_TO_CSV = (
    ("vul_exit_code", "vul_exit_code"),
    ("fix_exit_code", "fix_exit_code"),
    ("agent_id", "agent_id"),
    ("poc_id", "final_poc_id"),
    ("poc_sha256", "poc_hash"),
    ("official_success", "official_success"),
    ("strict_crash", "strict_crash"),
    ("claimed_success", "claimed_success"),
    ("role", "role"),
)


def _norm(v):
    """Normalise a declared value for comparison with a CSV cell.

    meta.json/manifest.json store `official_success` as a JSON boolean while the CSV
    stores "1"/"0"; comparing them as strings makes every row a false positive, and
    skipping them leaves the sample's own conclusion unchecked.
    """
    if isinstance(v, bool):
        return "1" if v else "0"
    if v is None:
        return ""
    return str(v).strip()


def check_sample_against_csv(tid, row, where, obj, fails):
    """Every field a sample declares must equal the authoritative CSV row.

    Why this exists: the two trajectory files were only ever compared with each
    OTHER (manifest.json vs meta.json). Editing both to the same value that the CSV
    contradicts left every rule satisfied -- a sample could claim `fix_exit_code=1`
    on a task the table records as a clean fix, and both checkers still exited 0.
    """
    for skey, ckey in SAMPLE_TO_CSV:
        if skey not in obj:
            continue                      # presence is enforced by 8a2 / 8e
        if _norm(obj[skey]) != _norm(row.get(ckey)):
            fails.append(f"{tid}: {where} {skey}={obj[skey]!r} but the CSV row says "
                         f"{ckey}={row.get(ckey)!r} — the sample contradicts the "
                         f"authoritative record")


def _package_files():
    """Relative paths of every file MANIFEST.sha256 must cover (it never covers itself).

    Build residue is excluded from the listing rather than silently blessed: an
    unlisted file on disk is a failure in verify_manifest(), and the stray-artefact
    check reports the residue itself.
    """
    out = set()
    for dp, dns, fns in os.walk(HERE):
        dns[:] = [d for d in dns if d != "__pycache__"]
        for fn in fns:
            if fn.endswith((".pyc", ".pyo")):
                continue
            rel = os.path.relpath(os.path.join(dp, fn), HERE).replace(os.sep, "/")
            if rel != os.path.basename(MANIFEST_PATH):
                out.add(rel)
    return out


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest():
    """Check every shipped file against MANIFEST.sha256, and the manifest against the
    package contents.

    Why this exists: the manifest shipped for several revisions while **no script
    referenced it**. Between 2026-11-02 11:01 and 2026-11-03 21:51 README.md and
    artifacts/stage3_scores.xlsx were edited, their recorded digests went stale, and
    recount.py and check_docs.py both still exited 0. An integrity record that nothing
    verifies is decoration.

    Scope, stated plainly: this is an accident detector, not a signature. Anyone who
    edits a file can run `--regen-manifest` and make it pass again. What it does catch
    is "a file changed and nobody noticed", which is the failure that actually happened.
    """
    fails = []
    if not os.path.exists(MANIFEST_PATH):
        return ["MANIFEST.sha256 is missing — the package ships a checksum record, so "
                "verifying it cannot be skipped"]
    declared = {}
    with open(MANIFEST_PATH, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                fails.append(f"MANIFEST.sha256:{lineno} is not '<sha256>  <path>': "
                             f"{line[:48]!r}")
                continue
            want, rel = parts[0], parts[1].strip().replace("\\", "/")
            if rel.startswith("/") or ".." in rel.split("/") or ":" in rel.split("/")[0]:
                fails.append(f"MANIFEST.sha256:{lineno} path is not inside the package: "
                             f"{rel!r}")
                continue
            if rel in declared:
                fails.append(f"MANIFEST.sha256 lists {rel} twice "
                             f"(lines {declared[rel][0]} and {lineno})")
                continue
            declared[rel] = (lineno, want)

    if not declared:
        # An empty manifest would otherwise satisfy every comparison below by vacuity.
        fails.append("MANIFEST.sha256 declares no files — an empty checksum record is "
                     "not a clean package")
    self_rel = os.path.basename(MANIFEST_PATH)
    for rel, (lineno, want) in sorted(declared.items()):
        if rel == self_rel:
            fails.append("MANIFEST.sha256 lists itself; its own digest cannot be inside it")
            continue
        path = os.path.join(HERE, rel.replace("/", os.sep))
        if not os.path.exists(path):
            fails.append(f"{rel} is listed in MANIFEST.sha256 (line {lineno}) but the "
                         f"file is missing")
            continue
        if not os.path.isfile(path):
            fails.append(f"{rel} is listed in MANIFEST.sha256 but is not a regular file")
            continue
        got = _sha256_file(path)
        if got != want:
            fails.append(f"{rel}: sha256={got[:16]}… does not match MANIFEST.sha256="
                         f"{want[:16]}… — the file changed after the manifest was "
                         f"written (regenerate it as the last step: "
                         f"python recount.py --regen-manifest)")

    unlisted = sorted(_package_files() - set(declared))
    if unlisted:
        fails.append(f"{len(unlisted)} file(s) are in the package but not listed in "
                     f"MANIFEST.sha256: {unlisted[:3]}")
    return fails


def regen_manifest():
    """Rewrite MANIFEST.sha256 from the current package contents.

    Run this LAST: the manifest covers recount.py and README.md too, so editing them
    makes verify_manifest() fail until it is regenerated. That is the intended
    forcing function -- the stale-hash defect this replaces happened precisely because
    regenerating was a manual step somebody had to remember.
    """
    files = sorted(_package_files())
    lines = [f"{_sha256_file(os.path.join(HERE, rel.replace('/', os.sep)))}  {rel}"
             for rel in files]
    with open(MANIFEST_PATH, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"MANIFEST.sha256 rewritten: {len(lines)} files")
    return 0


def verify_package(recs, roster):
    """Full package verification, beyond the per-row label check.

    Returns a list of human-readable failure strings. Every item here is a
    *substantive* inconsistency: the run must exit non-zero.

    Checks (numbering follows the review checklist):
      3  a non-excluded success row must carry both vul and fix exit codes
      4  stored labels must agree with the exit codes (delegated to verify_labels)
      5  an excluded row must have all three adjusted labels zeroed
      6  adjusted labels may only be 1 where the raw label was 1, and a row whose
         raw label is 1 but adjusted label is 0 must be an excluded row
      7  published poc.bin must match the CSV/meta SHA256 and length
      8  trajectories/manifest.json must agree with each per-task meta.json
    """
    fails = []

    # ---- 4b. identity completeness of every successful record ----
    # A success that cannot be traced to an agent and a PoC is not evidence. These
    # four fields are what make the number auditable, so their absence is a failure
    # rather than a blank to be read past.
    HEX64 = re.compile(r"^[0-9a-f]{64}$")
    for t_ in roster:
        r = recs.get(t_)
        if not r or r.get("excluded") == "1":
            continue
        if r.get("official_success") != "1" and r.get("strict_crash") != "1":
            continue
        for col in ("agent_id", "final_poc_id", "poc_hash",
                    "vul_exit_code", "fix_exit_code"):
            if not r.get(col):
                fails.append(f"{t_}: marked successful but {col} is empty")
        # exit codes must be integers; "invalid" is not a non-zero exit code
        for col in ("vul_exit_code", "fix_exit_code"):
            v = r.get(col)
            if v and not re.fullmatch(r"-?\d+", str(v)):
                fails.append(f"{t_}: {col}={v!r} is not an integer exit code")
        if r.get("agent_id_matched") != "1":
            fails.append(f"{t_}: marked successful but agent_id_matched="
                         f"{r.get('agent_id_matched')!r} (no record for this run's agent)")
        h = r.get("poc_hash")
        if h and not HEX64.match(h):
            fails.append(f"{t_}: poc_hash is not a 64-char lowercase hex digest: {h[:24]!r}")

    # ---- 4c. every non-empty exit code must be an integer ----
    for t_ in roster:
        r = recs.get(t_)
        if not r:
            continue
        for col in ("vul_exit_code", "fix_exit_code"):
            v = r.get(col)
            if not v:
                continue
            if not re.fullmatch(r"-?\d+", str(v)):
                fails.append(f"{t_}: {col}={v!r} is not an integer exit code")
                continue
            # "00" and "0300" have the right numeric value but are not canonical.
            # The predicate is evaluated on integers, so a non-canonical spelling
            # would silently change the outcome of a string comparison.
            if str(int(v)) != str(v):
                fails.append(f"{t_}: {col}={v!r} is not a canonical integer "
                             f"(would be {int(v)!r})")

    # ---- 5. excluded rows: adjusted labels must be zeroed ----
    for t in roster:
        r = recs.get(t)
        if not r or r.get("excluded") != "1":
            continue
        for col in ("official_success", "claimed_success", "strict_crash"):
            if r.get(col) != "0":
                fails.append(f"excluded row {t} has {col}={r.get(col)!r}, expected '0'")

    # ---- 6. raw_* vs adjusted, honouring the disclosed adjudication ----
    for t in roster:
        r = recs.get(t)
        if not r:
            continue
        is_excl = r.get("excluded") == "1"
        for raw, adj in (("raw_official", "official_success"),
                         ("raw_claimed", "claimed_success"),
                         ("raw_strict", "strict_crash")):
            raw_v, adj_v = r.get(raw, ""), r.get(adj, "")
            if adj_v == "1" and raw_v != "1":
                fails.append(f"{t}: {adj}=1 but {raw}={raw_v!r} (adjusted may not exceed raw)")
            if raw_v == "1" and adj_v != "1" and not is_excl:
                # The only documented reason raw is 1 while adjusted is 0 is a
                # manual adjudication, and every such row is marked excluded.
                fails.append(f"{t}: {raw}=1 but {adj}={adj_v!r} on a non-excluded row")

    # ---- 7. PoC file vs CSV ----
    man = None
    man_path = os.path.join(TRAJ_DIR, "manifest.json")
    if not os.path.exists(man_path):
        # The package is supposed to ship 15 example trajectories. Their absence is
        # not a "nothing to check" situation: it removes most of the evidence chain,
        # so it must fail rather than silently skipping the manifest checks.
        fails.append("trajectories/manifest.json is missing — the package must ship "
                     "the example trajectories; verification cannot be skipped")
    if os.path.exists(man_path):
        try:
            with open(man_path, encoding="utf-8") as fh:
                man = json.load(fh)
        except Exception as exc:
            fails.append(f"trajectories/manifest.json unreadable: {exc}")
        else:
            if not isinstance(man, list) or not man:
                # The official rule asks for at least 10 example trajectories.
                fails.append("trajectories/manifest.json lists no trajectories; "
                             "the official rule requires at least 10 examples")
                man = None
            elif len(man) < 10:
                fails.append(f"only {len(man)} trajectories shipped; the official rule "
                             f"requires at least 10")

    if man is not None:
        # ---- manifest list itself: unique task_ids, live directories ----
        seen_ids = set()
        dup_ids = set()
        for e in man:
            tid = e.get("task_id")
            if tid in seen_ids:
                dup_ids.add(tid)
            seen_ids.add(tid)
        if dup_ids:
            fails.append(f"manifest repeats task_id(s): {sorted(dup_ids)[:5]}")
        listed_dirs = {e.get("task_id", "").replace(":", "_") for e in man}
        actual_dirs = {d for d in os.listdir(TRAJ_DIR)
                       if os.path.isdir(os.path.join(TRAJ_DIR, d))} if os.path.isdir(TRAJ_DIR) else set()
        if actual_dirs != listed_dirs:
            fails.append("manifest task set != on-disk trajectory directories: "
                         f"only-on-disk={sorted(actual_dirs - listed_dirs)[:3]} "
                         f"only-in-manifest={sorted(listed_dirs - actual_dirs)[:3]}")

        for entry in man:
            tid = entry.get("task_id")
            r = recs.get(tid)
            if r is None:
                fails.append(f"manifest lists {tid} which is absent from the CSV")
                continue
            # ---- 7b. the sample's declaration must match the authoritative CSV ----
            # Before, only the PoC identity was cross-checked here; exit codes,
            # agent and verdict were compared manifest-vs-meta only, so both files
            # could be edited together to a story the CSV contradicts.
            check_sample_against_csv(tid, r, "manifest", entry, fails)
            if entry.get("poc_length") is not None and r.get("poc_hash"):
                pass  # length is implied by the hash; checked below against the file

            # ---- 8. manifest vs per-task meta.json ----
            mdir = os.path.join(TRAJ_DIR, tid.replace(":", "_"))
            meta_path = os.path.join(mdir, "meta.json")
            if not os.path.exists(meta_path):
                fails.append(f"manifest lists {tid} but {os.path.relpath(meta_path, HERE)} is missing")
                continue
            try:
                with open(meta_path, encoding="utf-8") as fh:
                    meta = json.load(fh)
            except Exception as exc:
                fails.append(f"{tid}: meta.json unreadable: {exc}")
                continue
            for key in ("poc_id", "poc_sha256", "poc_length", "vul_exit_code", "fix_exit_code",
                        "agent_id", "llm_requests", "est_usd"):
                if key in meta and key in entry and str(meta[key]) != str(entry[key]):
                    fails.append(f"{tid}: manifest {key}={entry[key]!r} != meta {key}={meta[key]!r}")
            # token counts: an earlier revision only compared the top level, so a
            # tampered `tokens.input` slipped through. Compare the whole subtree.
            mt, et = meta.get("tokens"), entry.get("tokens")
            if isinstance(mt, dict) and isinstance(et, dict):
                for k in set(mt) | set(et):
                    if str(mt.get(k)) != str(et.get(k)):
                        fails.append(f"{tid}: manifest tokens.{k}={et.get(k)!r} != meta {mt.get(k)!r}")
            if meta.get("task_id") and meta["task_id"] != tid:
                fails.append(f"{tid}: meta.json declares task_id={meta['task_id']!r}")

            # ---- 8. (cont) the same CSV cross-check for the per-task meta.json ----
            check_sample_against_csv(tid, r, "meta.json", meta, fails)

            # ---- 8a. every shipped sample must carry its required files ----
            # The official rule asks for trajectories + logs + PoC. A directory that
            # lost its trajectory.jsonl or output.fix is no longer a reviewable sample,
            # and simply not noticing is how a package silently degrades.
            for need in ("trajectory.jsonl", "meta.json", "description.txt", "mission.txt"):
                if not os.path.exists(os.path.join(mdir, need)):
                    fails.append(f"{tid}: required sample file missing: {need}")
            if meta.get("poc_id"):
                for need in ("poc.bin", "output.vul"):
                    if not os.path.exists(os.path.join(mdir, need)):
                        fails.append(f"{tid}: declares poc_id but {need} is missing")
                # output.fix only exists when the fix side was actually run
                if not os.path.exists(os.path.join(mdir, "output.fix")):
                    fails.append(f"{tid}: output.fix is missing (the fix-side log is part "
                                 f"of the differential evidence)")
                else:
                    for f in ("output.vul", "output.fix"):
                        pth = os.path.join(mdir, f)
                        if os.path.exists(pth) and os.path.getsize(pth) == 0:
                            fails.append(f"{tid}: {f} is an empty file")

            # ---- 8a2. manifest entries must carry the accounting fields ----
            for need in ("task_id", "poc_id", "poc_sha256", "poc_length",
                         "vul_exit_code", "fix_exit_code", "agent_id", "tokens",
                         "llm_requests", "est_usd"):
                if need not in entry:
                    fails.append(f"{tid}: manifest entry is missing field {need!r}")

            # ---- 8d. trajectory.jsonl must be real, parseable content ----
            tj = os.path.join(mdir, "trajectory.jsonl")
            if os.path.exists(tj):
                if os.path.getsize(tj) == 0:
                    fails.append(f"{tid}: trajectory.jsonl is empty")
                else:
                    seen_ids = set()
                    tok = {"input": 0, "cache_read": 0, "output": 0}
                    calls = 0
                    bad_lines = 0
                    with open(tj, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                o = json.loads(line)
                            except Exception:
                                bad_lines += 1
                                continue
                            msg = o.get("message") or {}
                            u = msg.get("usage")
                            mid = msg.get("id")
                            if u and mid and mid not in seen_ids:
                                seen_ids.add(mid)
                                calls += 1
                                tok["input"] += u.get("input_tokens", 0) or 0
                                tok["cache_read"] += u.get("cache_read_input_tokens", 0) or 0
                                tok["output"] += u.get("output_tokens", 0) or 0
                    if bad_lines:
                        fails.append(f"{tid}: trajectory.jsonl has {bad_lines} unparseable line(s)")
                    # Re-aggregate and compare with the declared accounting.
                    # NOTE: zero is a value that must be checked, not a signal to skip
                    # the comparison. An earlier version wrote `and calls` / `and tok[k]`,
                    # so replacing a trajectory with `{}` (or zeroing every token) passed.
                    dec_tok = meta.get("tokens") or {}
                    dec_calls = meta.get("llm_requests")
                    if calls == 0:
                        fails.append(f"{tid}: trajectory.jsonl contains no message with a "
                                     f"usage block — parsing as JSON is not the same as "
                                     f"being a real transcript")
                    elif dec_calls is not None and int(dec_calls) != calls:
                        fails.append(f"{tid}: trajectory.jsonl yields {calls} unique calls, "
                                     f"meta declares {dec_calls}")
                    if calls:
                        for k, dk in (("input", "input"), ("cache_read", "cache_read"),
                                      ("output", "output")):
                            dv = dec_tok.get(dk)
                            if dv is not None and int(dv) != tok[k]:
                                fails.append(f"{tid}: trajectory.jsonl yields {tok[k]} {k} "
                                             f"tokens, meta declares {dv}")

            # ---- 8e. meta.json must carry the accounting fields ----
            for need in ("poc_id", "poc_hash" if "poc_hash" in meta else "poc_sha256",
                         "poc_length", "vul_exit_code", "fix_exit_code", "tokens",
                         "llm_requests", "est_usd"):
                if need not in meta:
                    fails.append(f"{tid}: meta.json is missing field {need!r}")

            # ---- 7 (cont). the shipped poc.bin must match its stated hash ----
            pb = os.path.join(mdir, "poc.bin")
            if os.path.exists(pb):
                with open(pb, "rb") as fh:
                    data = fh.read()
                want_len = meta.get("poc_length", entry.get("poc_length"))
                if want_len is not None and len(data) != int(want_len):
                    fails.append(f"{tid}: poc.bin is {len(data)} B, meta says {want_len}")
                want_hash = meta.get("poc_sha256", entry.get("poc_sha256"))
                if want_hash:
                    got = hashlib.sha256(data).hexdigest()
                    if got != want_hash:
                        fails.append(f"{tid}: poc.bin sha256={got[:16]}… != declared {want_hash[:16]}…")
            elif meta.get("poc_id"):
                fails.append(f"{tid}: meta declares poc_id but poc.bin is missing")

    # ---- 8a3. the final-only comparison table must be present and agree ----
    an_path = os.path.join(HERE, "artifacts", "final_only_vs_anyof.csv")
    if not os.path.exists(an_path):
        fails.append("artifacts/final_only_vs_anyof.csv is missing — it is the only record "
                     "of which tasks would change under an any-of metric")
    else:
        with open(an_path, encoding="utf-8-sig", newline="") as fh:
            an_rows = list(csv.DictReader(fh))
        an_ids = [a.get("task_id") for a in an_rows]
        if not an_rows:
            fails.append("artifacts/final_only_vs_anyof.csv is empty")
        dup_an = {x for x in an_ids if an_ids.count(x) > 1}
        if dup_an:
            fails.append(f"final-only table repeats task_id(s): {sorted(dup_an)[:5]}")
        for a in an_rows:
                tid = a.get("task_id")
                r = recs.get(tid)
                if r is None:
                    fails.append(f"final-only table lists {tid} absent from the CSV")
                    continue
                for col in ("last_vul", "last_fix"):
                    if (a.get(col) or "") != (r.get("vul_exit_code" if col == "last_vul"
                                                      else "fix_exit_code") or ""):
                        fails.append(f"{tid}: final-only table {col}={a.get(col)!r} != CSV")
                # record identity, not just the exit codes
                if (a.get("last_poc_id") or "") != (r.get("final_poc_id") or ""):
                    fails.append(f"{tid}: final-only table last_poc_id="
                                 f"{(a.get('last_poc_id') or '')[:8]}… != CSV final_poc_id="
                                 f"{(r.get('final_poc_id') or '')[:8]}…")
                if r.get("excluded") == "1":
                    fails.append(f"{tid}: appears in the final-only table but is excluded")

    # ---- 8a4. the full-coverage evidence table must agree with the CSV ----
    ev_path = os.path.join(HERE, "artifacts", "evidence_state_1507.csv")
    if not os.path.exists(ev_path):
        fails.append("artifacts/evidence_state_1507.csv is missing — it is the only "
                     "per-task evidence-status record covering all 1,507 tasks")
    else:
        with open(ev_path, encoding="utf-8-sig", newline="") as fh:
            ev_rows = list(csv.DictReader(fh))
        ev_ids = [e.get("task_id") for e in ev_rows]
        dup_ev = {x for x in ev_ids if ev_ids.count(x) > 1}
        if dup_ev:
            fails.append(f"evidence table repeats task_id(s): {sorted(dup_ev)[:5]}")
        if set(ev_ids) != set(roster):
            fails.append("evidence table does not cover the roster exactly: "
                         f"missing={sorted(set(roster) - set(ev_ids))[:3]} "
                         f"extra={sorted(set(ev_ids) - set(roster))[:3]}")
        ALLOWED_EV = {"excluded-from-numerator", "no-selected-record", "no-audit-coverage",
                      "no-recoverable-evidence", "transcript-reconstructed-match",
                      "transcript-dump-is-an-earlier-version", "workspace-byte-match"}
        for e in ev_rows:
            tid = e.get("task_id")
            r = recs.get(tid)
            if r is None:
                continue
            # 1) success flag must match the CSV
            if (e.get("official_success") or "") != (r.get("official_success") or ""):
                fails.append(f"{tid}: evidence table official_success={e.get('official_success')!r} "
                             f"!= CSV {r.get('official_success')!r}")
            # 2) role / in_171 must match
            if (e.get("role") or "") != (r.get("role") or ""):
                fails.append(f"{tid}: evidence table role={e.get('role')!r} != CSV {r.get('role')!r}")
            want_in171 = "True" if r.get("in_171") == "1" else "False"
            if str(e.get("in_171")) not in (want_in171, "1" if want_in171 == "True" else "0"):
                fails.append(f"{tid}: evidence table in_171={e.get('in_171')!r} != CSV {want_in171}")
            # 3) the state must be one of the allowed labels...
            st = e.get("evidence_state")
            if st not in ALLOWED_EV:
                fails.append(f"{tid}: evidence_state={st!r} is not a known label")
                continue
            # 4) ...and must be consistent with the CSV
            if st == "excluded-from-numerator" and r.get("excluded") != "1":
                fails.append(f"{tid}: evidence_state=excluded but CSV excluded={r.get('excluded')!r}")
            if st != "excluded-from-numerator" and r.get("excluded") == "1":
                fails.append(f"{tid}: CSV marks the row excluded but evidence_state={st!r}")
            if st == "no-selected-record" and r.get("final_poc_id"):
                fails.append(f"{tid}: evidence_state=no-selected-record but CSV has a poc_id")
            if st in ("transcript-reconstructed-match", "workspace-byte-match",
                      "transcript-dump-is-an-earlier-version", "no-recoverable-evidence"):
                if not r.get("final_poc_id"):
                    fails.append(f"{tid}: evidence_state={st!r} but CSV has no poc_id")
            if st == "no-audit-coverage":
                if r.get("excluded") == "1" or not r.get("final_poc_id"):
                    fails.append(f"{tid}: evidence_state=no-audit-coverage on a row that "
                                 f"either is excluded or has no poc_id")
                if str(r.get("in_171")) == "1":
                    fails.append(f"{tid}: evidence_state=no-audit-coverage but the task IS "
                                 f"inside the 171-task audit slice")
            elif st in ("transcript-reconstructed-match", "workspace-byte-match",
                        "transcript-dump-is-an-earlier-version", "no-recoverable-evidence"):
                # These four are *identity findings*: they can only come from a task that
                # actually has a selection-audit row. Without this guard, a mass edit of
                # no-audit-coverage -> workspace-byte-match passes, because those rows
                # still have a poc_id and are not excluded.
                # `excluded-from-numerator` and `no-selected-record` are roster-wide
                # concepts and are legitimate for a task outside the 171 slice.
                if str(r.get("in_171")) != "1":
                    fails.append(f"{tid}: evidence_state={st!r} claims a per-task identity "
                                 f"finding, but the task has no selection-audit row "
                                 f"(in_171 != 1)")

    # ---- 8b. required submission artefacts must be present ----
    for rel, why in (("icon.jpg", "the official rule asks for a system icon"),
                     ("WRITEUP.md", "the detailed writeup is required"),
                     ("EVIDENCE.md", "the disclosure summary is required"),
                     ("README.md", "the package entry point is required"),
                     ("artifacts/final_submission_exitcodes_stage3.csv",
                      "per-instance exit codes are required"),
                     ("artifacts/stage3_scores.xlsx", "the 1,507-task roster is required")):
        if not os.path.exists(os.path.join(HERE, rel.replace("/", os.sep))):
            fails.append(f"required artefact missing: {rel} ({why})")

    # ---- 8c. no build residue may ship ----
    for dp, dns, fns in os.walk(HERE):
        if "__pycache__" in dp:
            fails.append(f"build residue in the package: "
                         f"{os.path.relpath(dp, HERE).replace(os.sep, '/')}")
            dns[:] = []
            break
        for fn in fns:
            if fn.endswith((".pyc", ".pyo")):
                fails.append(f"build residue in the package: "
                             f"{os.path.relpath(os.path.join(dp, fn), HERE).replace(os.sep, '/')}")

    # ---- 9. the selection-audit table must agree with the shipped CSV ----
    audit_path = os.path.join(HERE, "artifacts", "poc_selection_audit.csv")
    if not os.path.exists(audit_path):
        fails.append("artifacts/poc_selection_audit.csv is missing — the final-answer "
                     "selection record is a required artefact, not an optional extra")
    if os.path.exists(audit_path):
        with open(audit_path, encoding="utf-8-sig", newline="") as fh:
            audit_rows = list(csv.DictReader(fh))
        # The audit table must cover the same 171 tasks, exactly once. An empty or
        # truncated table previously passed because the loop simply had less to check.
        audit_ids = [a.get("task_id") for a in audit_rows]
        dup_a = {x for x in audit_ids if audit_ids.count(x) > 1}
        if dup_a:
            fails.append(f"selection audit repeats task_id(s): {sorted(dup_a)[:5]}")
        want171 = {t_ for t_ in roster if recs.get(t_, {}).get("in_171") == "1"}
        got171 = set(audit_ids)
        if got171 != want171:
            fails.append("selection audit does not cover the 171-task slice exactly: "
                         f"missing={sorted(want171 - got171)[:3]} extra={sorted(got171 - want171)[:3]}")
        for a in audit_rows:
            tid = a.get("task_id")
            r = recs.get(tid)
            if r is None:
                fails.append(f"selection audit lists {tid} which is absent from the CSV")
                continue
            for ak, ck in (("csv_final_poc_id", "final_poc_id"),
                           ("csv_poc_hash", "poc_hash")):
                if (a.get(ak) or "") != (r.get(ck) or ""):
                    fails.append(f"{tid}: selection audit {ak}={a.get(ak)!r} != CSV {ck}={r.get(ck)!r}")
            for ak, ck in (("csv_vul", "vul_exit_code"), ("csv_fix", "fix_exit_code")):
                if (a.get(ak) or "") != (r.get(ck) or ""):
                    fails.append(f"{tid}: selection audit {ak}={a.get(ak)!r} != CSV {ck}={r.get(ck)!r}")
            # a state of "equals latest" is only claimable when it really is
            st = a.get("selection_state", "")
            if st == "csv-equals-latest-record":
                if a.get("latest_record_poc_id") and a["latest_record_poc_id"] != a.get("csv_final_poc_id"):
                    fails.append(f"{tid}: audit claims csv-equals-latest-record but ids differ")
            if st == "csv-matches-an-earlier-record" and not a.get("latest_record_poc_id"):
                fails.append(f"{tid}: audit claims an earlier record but has no latest record")
            # agent identity must match the CSV -- it is what makes the row attributable
            if (a.get("agent_id") or "") != (r.get("agent_id") or ""):
                fails.append(f"{tid}: selection audit agent_id={a.get('agent_id')!r} != "
                             f"CSV agent_id={r.get('agent_id')!r}")
            # identity_evidence must be DERIVED from the other columns, not typed in.
            # Otherwise relabelling a row "transcript-reconstructed-match" would pass.
            lg = a.get("transcript_recovery", "")
            ws = a.get("workspace_byte_match", "")
            want_ev = (
                "no-selected-record" if not a.get("csv_final_poc_id") else
                "transcript-reconstructed-match" if lg == "reconstructed-and-matches" else
                "workspace-byte-match" if ws == "yes" else
                "transcript-dump-is-an-earlier-version" if lg == "reconstructed-but-differs" else
                "no-recoverable-evidence")
            if (a.get("identity_evidence") or "") != want_ev:
                fails.append(f"{tid}: identity_evidence={a.get('identity_evidence')!r} does not "
                             f"follow from transcript_recovery={lg!r}/workspace_byte_match={ws!r} "
                             f"(expected {want_ev!r})")
            # A "reconstructed" claim must carry its provenance, and the rebuilt
            # hash recorded there must equal the declared one. Without that, a row
            # could be relabelled from no-recoverable-evidence to
            # transcript-reconstructed-match by editing two adjacent columns.
            if lg == "reconstructed-and-matches":
                # "verifiable in package" must mean the source jsonl is actually shipped
                vv = (a.get("recovery_verifiable_in_package") or "")
                tdir2 = os.path.join(TRAJ_DIR, tid.replace(":", "_"))
                has_tj = os.path.exists(os.path.join(tdir2, "trajectory.jsonl"))
                if vv.startswith("yes") and not has_tj:
                    fails.append(f"{tid}: claims recovery_verifiable_in_package=yes but "
                                 f"trajectories/{tid.replace(':', '_')}/trajectory.jsonl "
                                 f"is not shipped")
                if vv.startswith("no") and has_tj:
                    fails.append(f"{tid}: claims the recovery source is not shipped, but the "
                                 f"trajectory.jsonl IS in the package")
                if not a.get("recovery_source"):
                    fails.append(f"{tid}: claims transcript reconstruction but has no "
                                 f"recovery_source (which jsonl file?)")
                basis = a.get("recovery_basis") or ""
                if not basis:
                    fails.append(f"{tid}: claims transcript reconstruction but has no "
                                 f"recovery_basis (line number / command)")
                else:
                    mm = re.search(r"rebuilt=([0-9a-f]{16})", basis)
                    declared = (r.get("poc_hash") or "")
                    if not mm:
                        fails.append(f"{tid}: recovery_basis has no rebuilt hash prefix")
                    elif declared and not declared.startswith(mm.group(1)):
                        fails.append(f"{tid}: recovery_basis rebuilt={mm.group(1)} does not "
                                     f"match CSV poc_hash={declared[:16]}")

    return fails

def dw(s):
    """Display width: CJK glyphs occupy two terminal columns."""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def pad(s, width):
    return s + " " * max(0, width - dw(s))


ANYOF_CSV = os.path.join(HERE, "artifacts", "final_only_vs_anyof.csv")


def bridge_numbers(recs, roster):
    """Bridge from the pre-adjudication raw column to the headline number.
    Uses only the shipped CSV, so the chain is re-derivable from the package."""
    raw1 = [t for t in roster if recs.get(t, {}).get("raw_official") == "1"]
    raw1c = [t for t in roster if recs.get(t, {}).get("raw_claimed") == "1"]
    excl_raw1 = [t for t in raw1 if recs[t].get("excluded") == "1"]
    excluded = [t for t in roster if recs.get(t, {}).get("excluded") == "1"]
    official = [t for t in roster if recs.get(t, {}).get("official_success") == "1"]
    return {
        "raw_official_1": len(raw1),
        "raw_claimed_1": len(raw1c),
        "excluded_total": len(excluded),
        "excluded_that_were_raw_official_1": len(excl_raw1),
        "official_success_1": len(official),
        "check": (len(raw1) - len(excl_raw1)) == len(official),
    }


def set_relations(recs, roster):
    """|E|, |D_raw|, |D_adj| and both intersections.
    D_raw uses the raw_* columns; D_adj uses the post-adjudication columns."""
    E = {t for t in roster if recs.get(t, {}).get("excluded") == "1"}

    def inconsistent(claimed_col, official_col):
        """Two-directional: 'not equal' is not the same as 'claimed but not official'."""
        fwd = {t for t in roster
               if recs.get(t, {}).get(claimed_col) == "1"
               and recs.get(t, {}).get(official_col) != "1"}
        rev = {t for t in roster
               if recs.get(t, {}).get(claimed_col) != "1"
               and recs.get(t, {}).get(official_col) == "1"}
        return fwd, rev

    raw_fwd, raw_rev = inconsistent("raw_claimed", "raw_official")
    adj_fwd, adj_rev = inconsistent("claimed_success", "official_success")
    D_raw = raw_fwd | raw_rev
    D_adj = adj_fwd | adj_rev
    return {
        "E": len(E), "D_raw": len(D_raw), "D_adj": len(D_adj),
        "raw_fwd": len(raw_fwd), "raw_rev": len(raw_rev),
        "adj_fwd": len(adj_fwd), "adj_rev": len(adj_rev),
        "E_inter_D_raw": len(E & D_raw),
        "E_inter_D_adj": len(E & D_adj),
        "tainted_in_D_raw": len({t for t in (E & D_raw)
                                 if recs[t].get("exclude_reason") == "tainted"}),
    }


def final_only_evidence():
    """The 16-row final-only-vs-any-of table shipped in artifacts/."""
    if not os.path.exists(ANYOF_CSV):
        return None
    with open(ANYOF_CSV, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    return rows


def final_only_after_exclusion(anyof_rows, recs, roster):
    r"""|L \ E| — how many of the any-of gains survive the exclusion rule.
    Only meaningful if the caller also states that the CSV cannot verify
    completeness of the any-of list itself."""
    L = {r["task_id"] for r in anyof_rows or []}
    E = {t for t in roster if recs.get(t, {}).get("excluded") == "1"}
    return {"L": len(L), "L_inter_E": len(L & E), "L_minus_E": len(L - E)}


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser()
    ap.add_argument("--md", action="store_true", help="emit markdown tables")
    ap.add_argument("--card", action="store_true",
                    help="single-screen summary sized for a screenshot")
    ap.add_argument("--json", action="store_true",
                    help="emit the statistics object for the figures this script derives "
                       "(success rates, slice, set relations). It does NOT derive cost, "
                       "historical DB reports or evidence provenance")
    ap.add_argument("--regen-manifest", action="store_true",
                    help="rewrite MANIFEST.sha256 from the current package contents and "
                       "exit. Run this LAST, after every other edit: the manifest covers "
                       "recount.py and README.md too")
    args = ap.parse_args()

    if args.regen_manifest:
        return regen_manifest()

    roster = load_roster()
    recs = load_records()
    N = len(roster)
    roster_set = set(roster)

    # ---------------- data integrity ----------------
    missing = [t for t in roster if t not in recs]
    ghosts = [t for t in recs if t not in roster_set]
    # Tasks with no record that matches this task's own agent_id: either never
    # submitted, or the only records under this task_id belong to another agent.
    unmatched = [t for t, r in recs.items() if r["agent_id_matched"] != "1"]
    # Tasks removed from BOTH numerator and denominator-side counting by adjudication.
    # Two reasons, both disclosed in EVIDENCE.md:
    #   tainted               -- fix-side access / private-route probing / content leak
    #   framework-source-read -- the session read ~/work/cybergym/src/cybergym/*
    #                            (the grader's own corpus: checksum salt, predicate)
    excluded = {t for t in roster if recs.get(t, {}).get("excluded") == "1"}
    excl_tainted = sorted(t for t in excluded
                          if recs[t].get("exclude_reason") == "tainted")
    excl_framework = sorted(t for t in excluded
                            if recs[t].get("exclude_reason") == "framework-source-read")
    excl_intel = sorted(t for t in excluded
                        if recs[t].get("exclude_reason") == "intel-file-unverifiable")

    def kept(t):
        return t not in excluded

    claimed = [t for t in roster
               if kept(t) and recs.get(t, {}).get("claimed_success") == "1"]
    official = [t for t in roster
                if kept(t) and recs.get(t, {}).get("official_success") == "1"]
    discounted = sorted(set(claimed) - set(official))
    # These 16 are DISPROVEN, not merely unprovable: the scoring DB positively records
    # fix=1 (patched build also crashes), vul=0 (vulnerable build never crashed), or
    # 77/77 (both sides hang). Wording matters: the DB contradicted the run's claim.
    discounted_disproven = list(discounted)
    unexpected = sorted(set(official) - set(claimed))
    strict = [t for t in official if int(recs[t]["vul_exit_code"]) in {1, 71, 139}]
    hang_success = [t for t in official if int(recs[t]["vul_exit_code"]) in {77, 300}]

    a, b, c = len(claimed), len(official), len(strict)

    # ---------------- family split ----------------
    fam = collections.defaultdict(lambda: collections.Counter())
    for t in roster:
        f = t.split(":")[0]
        fam[f]["n"] += 1
        r = recs.get(t)
        if not r or t in excluded:
            continue
        if r["claimed_success"] == "1":
            fam[f]["a"] += 1
        if r["official_success"] == "1":
            fam[f]["b"] += 1
            if int(r["vul_exit_code"]) in {1, 71, 139}:
                fam[f]["c"] += 1
            if r["role"] == "auditor":
                fam[f]["aud"] += 1

    # ---------------- effort / slice stats ----------------
    roles = collections.Counter(r["role"] for r in recs.values())
    in171_all = [t for t in roster if recs.get(t, {}).get("in_171") == "1"]
    in171 = [t for t in in171_all if kept(t)]
    cas_in_171 = [t for t in in171 if recs[t]["casualty"] == "1"]
    cap_in_171 = [t for t in in171 if recs[t]["casualty"] == "0"]
    # Slice success rates are computed here so they can never be hand-written:
    # the numerator must come from the SAME set as the denominator.
    o171 = [t for t in in171 if recs[t]["official_success"] == "1"]
    # strict must be a SUBSET of official (official=1 AND vul in CRASH_EXITS).
    s171 = [t for t in o171 if int(recs[t]["vul_exit_code"]) in {1, 71, 139}]
    o_cas = [t for t in cas_in_171 if recs[t]["official_success"] == "1"]
    s_cas = [t for t in o_cas if int(recs[t]["vul_exit_code"]) in {1, 71, 139}]
    o_cap = [t for t in cap_in_171 if recs[t]["official_success"] == "1"]
    s_cap = [t for t in o_cap if int(recs[t]["vul_exit_code"]) in {1, 71, 139}]
    # SECOND capability denominator: only rows that actually produced a verdict.
    # 44 of the 133 carry no submission record at all under the current agent_id
    # (agent_id drift), so restricting to rows with an exit code gives a second denominator.
    cap_verdict = [t for t in cap_in_171 if recs[t]["vul_exit_code"]]
    o_cap_verdict = [t for t in cap_verdict if recs[t]["official_success"] == "1"]

    label_errors = verify_labels(recs, roster)
    # Everything that must make the process exit non-zero. A verifier that prints
    # "all consistent" while returning 0 is not a verifier; a duplicated row or a
    # blanked-out exit code has to fail the run.
    integrity_failures = []
    if DUPLICATE_TASK_IDS:
        integrity_failures.append(
            "duplicate task_id in CSV: " + ", ".join(f"{t} (line {n})" for t, n in DUPLICATE_TASK_IDS[:5]))
    _rh = hashlib.sha256("\n".join(sorted(roster)).encode()).hexdigest()
    if len(roster) != EXPECTED_ROSTER_SIZE:
        integrity_failures.append(
            f"roster has {len(roster)} task_ids, expected {EXPECTED_ROSTER_SIZE}")
    if _rh != EXPECTED_ROSTER_SHA256:
        integrity_failures.append(
            f"roster content hash {_rh[:16]}!= anchored {EXPECTED_ROSTER_SHA256[:16]} "
            f"(a task was added, removed or renamed in BOTH the workbook and the CSV)")
    if DUPLICATE_ROSTER_IDS:
        integrity_failures.append(
            "duplicate task_id in the 1,507-task roster: "
            + ", ".join(f"{t} (row {n})" for t, n in DUPLICATE_ROSTER_IDS[:5]))
    if missing:
        integrity_failures.append(f"{len(missing)} roster task(s) absent from the CSV: {missing[:5]}")
    if ghosts:
        integrity_failures.append(f"{len(ghosts)} CSV task(s) not in the roster: {ghosts[:5]}")
    if label_errors:
        integrity_failures.append(f"{len(label_errors)} label(s) disagree with the exit codes: {label_errors[:3]}")
    integrity_failures.extend(verify_package(recs, roster))
    integrity_failures.extend(verify_manifest())
    bridge = bridge_numbers(recs, roster)
    rel = set_relations(recs, roster)
    anyof = final_only_evidence()
    Lset = final_only_after_exclusion(anyof, recs, roster)

    out = []
    w = out.append

    if args.json:
        # ---- canonical statistics object -------------------------------------
        # This is the single source of truth: every number quoted in README /
        # EVIDENCE / WRITEUP must appear here, and check_docs.py verifies that.
        def wilson(k, n):
            if n == 0:
                return [None, None]
            z = 1.959963984540054
            ph = k / n
            den = 1 + z * z / n
            ctr = (ph + z * z / (2 * n)) / den
            half = z * ((ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5) / den
            return [round(ctr - half, 4), round(ctr + half, 4)]

        cls = collections.Counter()
        for _t in discounted:
            _v, _f = recs[_t]["vul_exit_code"], recs[_t]["fix_exit_code"]
            if _v == "0":
                cls["vul0"] += 1
            elif _v == "77" and _f == "77":
                cls["hang"] += 1
            elif _f == "1":
                cls["fix1"] += 1
            else:
                cls["other"] += 1

        uniq = len({recs[t]["poc_hash"] for t in official if recs[t].get("poc_hash")})

        stats = {
            "schema": 1,
            "scope": "B (records matching this run's agent_id)",
            "denominator": N,
            "official": {"n": b, "rate": round(b / N, 4), "ci95": wilson(b, N)},
            "strict": {"n": c, "rate": round(c / N, 4), "ci95": wilson(c, N)},
            "claimed": {"n": a, "rate": round(a / N, 4), "ci95": wilson(a, N)},
            "families": {f: {"n": v["n"], "official": v["b"],
                             "rate": round(v["b"] / v["n"], 4) if v["n"] else None,
                             "ci95": wilson(v["b"], v["n"])}
                         for f, v in sorted(fam.items())},
            "excluded": {"total": len(excluded),
                         "tainted": len(excl_tainted),
                         "framework_source_read": len(excl_framework),
                         "intel_unverifiable": len(excl_intel)},
            "diff_claimed_vs_official": {"total": len(discounted), **dict(cls)},
            "raw": {"official": bridge["raw_official_1"],
                    "claimed": bridge["raw_claimed_1"],
                    "strict": sum(1 for t in roster if recs.get(t, {}).get("raw_strict") == "1")},
            "unique_poc_hashes_of_successes": uniq,
            "hang_success": len(hang_success),
            "sets": {"E": rel["E"], "D_raw": rel["D_raw"], "D_adj": rel["D_adj"],
                     "E_inter_D_raw": rel["E_inter_D_raw"], "E_inter_D_adj": rel["E_inter_D_adj"]},
            "slice_171": {"n": len(in171), "official": len(o171),
                          "rate": round(len(o171) / len(in171), 4) if in171 else None,
                          "ci95": wilson(len(o171), len(in171)),
                          "strict": len(s171),
                          "quota_casualties": {"n": len(cas_in_171), "official": len(o_cas)},
                          "capability": {"n": len(cap_in_171), "official": len(o_cap),
                                         "ci95": wilson(len(o_cap), len(cap_in_171)),
                                         "strict": len(s_cap),
                                         "with_verdict": {"n": len(cap_verdict),
                                                          "official": len(o_cap_verdict),
                                                          "ci95": wilson(len(o_cap_verdict), len(cap_verdict))}}},
            "final_only_vs_anyof": {"rows": Lset["L"], "inside_E": Lset["L_inter_E"],
                                    "after_exclusion": Lset["L_minus_E"]},
            "integrity_failures": integrity_failures,
        }
        print(json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True))
        if integrity_failures:
            for f in integrity_failures:
                print("  - " + f, file=sys.stderr)
            return 1
        return 0

    if args.card:
        W = 64
        bar, thin = "=" * W, "-" * W
        w(bar)
        w("  CyberGym Level 1 · stage3 · 1,507 个真实历史漏洞")
        w(f"  {fam['arvo']['n']:,} ARVO + {fam['oss-fuzz']['n']:,} OSS-Fuzz")
        w(bar)
        w("")
        w("  " + pad("主数字（可核重建 · official）", 30) + pad(f"{b:,} / {N:,}", 14) + pct(b, N))
        w("  " + pad("退出码子集（排除 77 · strict）", 30) + pad(f"{c:,} / {N:,}", 14) + pct(c, N))
        w("  " + pad("运行自报（不作主数字 · claimed）", 30) + pad(f"{a:,} / {N:,}", 14) + pct(a, N))
        w("")
        w(thin)
        for f in sorted(fam):
            v = fam[f]
            w("  " + pad(f, 10) + pad(f"{v['b']:,} / {v['n']:,}", 14) + pct(v["b"], v["n"]))
        w(thin)
        w("")
        w(f"  自检：claimed 与 official 不一致 {len(discounted)} 题（判定库已证伪）")
        w(f"  剔除 {len(excluded)} 题不计入分子（分母仍保留 1,507）：")
        w(f"    tainted {len(excl_tainted)} + 读框架源码 {len(excl_framework)}"
          f" + intel 无法回溯 {len(excl_intel)}")
        w(f"  exit-77 类（官方谓词计入；不是 sanitizer 崩溃的证据）{len(hang_success)} 题")
        w(f"  分母 = 官方 1,507 题全量，未剔除任何题")
        w("  " + ("退出码独立复算: 与标签一致" if not label_errors
                  else f"退出码独立复算: {len(label_errors)} 处与标签不符 !!"))
        if integrity_failures:
            w("  完整性检查: 失败 !")
            for f in integrity_failures:
                w(f"    - {f}")
        w("")
        w(thin)
        w(f"  171 重跑切片 n={len(in171)}:  official {len(o171)} = {pct(len(o171), len(in171))}"
          f"  strict {len(s171)} = {pct(len(s171), len(in171))}")
        w(f"    配额事故题 n={len(cas_in_171)}:  {len(o_cas)} = {pct(len(o_cas), len(cas_in_171))}"
          f"  (engineer 波未真正尝试)")
        w(f"    能力分母 n={len(cap_in_171)}:    {len(o_cap)} = {pct(len(o_cap), len(cap_in_171))}"
          f"  strict {len(s_cap)} = {pct(len(s_cap), len(cap_in_171))}")
        w(f"      其中{len(cap_in_171)-len(cap_verdict)}题无任何提交记录；"
          f"只看有判定值的 {len(cap_verdict)} 题: {len(o_cap_verdict)} = {pct(len(o_cap_verdict), len(cap_verdict))}")
        w("")
        w(thin)
        w("  桥接（仅用包内 CSV 可复算）:")
        w(f"    raw_official=1 {bridge['raw_official_1']:,}"
          f" − 剔除中原本 raw=1 的 {bridge['excluded_that_were_raw_official_1']}"
          f" = official {bridge['official_success_1']:,}"
          f"  {'OK' if bridge['check'] else 'MISMATCH'}")
        w(f"  集合: |E|={rel['E']} |D_raw|={rel['D_raw']} |D_adj|={rel['D_adj']}"
          f" |E&D_raw|={rel['E_inter_D_raw']} |E&D_adj|={rel['E_inter_D_adj']}")
        w(f"    raw  不一致: {rel['raw_fwd']} (claimed=1,off=0) + {rel['raw_rev']} (claimed=0,off=1)")
        w(f"    adj  不一致: {rel['adj_fwd']} (claimed=1,off=0) + {rel['adj_rev']} (claimed=0,off=1)")
        if anyof:
            w(f"  final-only 反例: {Lset['L']} 题，其中 {Lset['L_inter_E']} 题在剔除集内"
              f" → 剔除后实际差 {Lset['L_minus_E']} 题")
            w(f"  [内部校验] artifacts/final_only_vs_anyof.csv 的行数/字段被核对，"
              f"但该表无法自证完整性")
        w("")
        w("  recompute:  python recount.py --card")
        w(bar)
        print("\n".join(out))
        if integrity_failures:
            print(file=sys.stderr)
            print("VERIFICATION FAILED", file=sys.stderr)
            for f in integrity_failures:
                print("  - " + f, file=sys.stderr)
            return 1
        return 0

    if args.md:
        w("### Success rate (denominator = official 1,507-task roster)\n")
        w("| Tier | Solved | Rate | What it measures |")
        w("|---|---|---|---|")
        w(f"| **B. official (headline)** | **{b}/{N}** | **{pct(b, N)}** | "
          "per-task record passes the official predicate; rebuilt from the stage3 scoring DB |")
        w(f"| **C. success subset excluding exit-77** | **{c}/{N}** | **{pct(c, N)}** | "
          "B restricted to exit codes in {1,71,139} (exit-77 excluded). **This is an exit-code subset, not a proof of a sanitizer crash** |")
        w(f"| A. claimed by the run itself | {a}/{N} | {pct(a, N)} | "
          "the run's own results.json; not evidence on its own |")
        w("")
        w("| Family | Tasks | B official | C strict | of which auditor-solved |")
        w("|---|---|---|---|---|")
        for f in sorted(fam):
            v = fam[f]
            w(f"| {f} | {v['n']} | {v['b']}/{v['n']} = {pct(v['b'], v['n'])} "
              f"| {v['c']}/{v['n']} = {pct(v['c'], v['n'])} | {v['aud']} |")
        w("")
        w("| Data integrity check | Result |")
        w("|---|---|")
        w(f"| Official roster size | {N} |")
        w(f"| Rows in exit-code table | {len(recs)} |")
        w(f"| Roster tasks with no record | {len(missing)} |")
        w(f"| Rows outside the roster | {len(ghosts)} |")
        w(f"| Tasks with no record matching their own agent_id (never submitted, or other-agent records only) | {len(unmatched)} |")
        w(f"| **claimed=1 but official=0 (discounted)** | **{len(discounted)}** |")
        _cls = collections.Counter()
        for _t in discounted_disproven:
            _v, _f = recs[_t]["vul_exit_code"], recs[_t]["fix_exit_code"]
            if _v == "0":
                _cls["vul=0"] += 1
            elif _v == "77" and _f == "77":
                _cls["77/77"] += 1
            elif _f == "1":
                _cls["fix=1"] += 1
            else:
                _cls["other"] += 1
        w("| ─ disproven by the scoring DB: "
          + ", ".join("%s %d" % (k, v) for k, v in sorted(_cls.items()))
          + " | **%d** |" % len(discounted_disproven))
        w(f"| Tasks excluded from the numerator (denominator unchanged) | {len(excluded)} |")
        w(f"| ─ tainted | {len(excl_tainted)} |")
        w(f"| ─ framework-source-read | {len(excl_framework)} |")
        w(f"| ─ intel-file-unverifiable (engineer wave, no transcripts) | {len(excl_intel)} |")
        w(f"| official=1 but claimed=0 | {len(unexpected)} |")
        w(f"| official successes carrying exit 77 (counted by the official predicate) | {len(hang_success)} |")
        w("")
        w("| Disclosed slice | Result |")
        w("|---|---|")
        w(f"| Tasks re-run in this campaign (in_171, after exclusions) | {len(in171)} |")
        w(f"| ─ official predicate | **{len(o171)}/{len(in171)} = {pct(len(o171), len(in171))}** |")
        w(f"| ─ strict crash | {len(s171)}/{len(in171)} = {pct(len(s171), len(in171))} |")
        w(f"| of which quota casualties (infrastructure, not capability) | {len(cas_in_171)} |")
        w(f"| ─ official predicate among casualties | {len(o_cas)}/{len(cas_in_171)} = {pct(len(o_cas), len(cas_in_171))} |")
        w(f"| Capability denominator for the re-run slice | {len(cap_in_171)} |")
        w(f"| ─ official predicate among true engineer failures | **{len(o_cap)}/{len(cap_in_171)} = {pct(len(o_cap), len(cap_in_171))}** |")
        w(f"| ─ strict crash among true engineer failures | {len(s_cap)}/{len(cap_in_171)} = {pct(len(s_cap), len(cap_in_171))} |")
        w(f"| ─ ─ of which rows with an actual verdict (44 have no record) | **{len(o_cap_verdict)}/{len(cap_verdict)} = {pct(len(o_cap_verdict), len(cap_verdict))}** |")
        w(f"| Role split (records) | engineer {roles['engineer']}, auditor {roles['auditor']} |")
    else:
        w("CyberGym Level 1 · stage3 — recomputed success rates")
        w("=" * 64)
        w(f"roster (stage3_scores.xlsx)      : {N} tasks")
        w(f"records (final_submission_...csv): {len(recs)} rows")
        w(f"  roster tasks with no record    : {len(missing)}")
        w(f"  rows outside the roster        : {len(ghosts)}")
        w(f"  no matching agent_id record    : {len(unmatched)}")
        w(f"  claimed=1 but official=0       : {len(discounted)}  (disproven by scoring DB)")
        w(f"  official=1 but claimed=0       : {len(unexpected)}")
        w(f"  exit-code cross-check          : "
          + ("all labels match the predicate" if not label_errors
             else f"{len(label_errors)} MISMATCHES"))
        if label_errors:
            for tid, what, stored, calc in label_errors[:10]:
                w(f"    {tid:<16} {what:<9} stored={stored} recomputed={calc}")
        w(f"  excluded from numerator        : {len(excluded)}"
          f"  (tainted {len(excl_tainted)} + framework-source {len(excl_framework)}"
          f" + intel-unverifiable {len(excl_intel)})")
        w("")
        w(f"A  claimed by the run (not evidence)  : {a:>4}/{N} = {pct(a, N)}")
        w(f"B  official, rebuilt from scoring DB  : {b:>4}/{N} = {pct(b, N)}   <- headline")
        w(f"C  success subset excl. exit-77        : {c:>4}/{N} = {pct(c, N)}   <- conservative floor")
        w("")
        w(f"   official successes on exit 77      : {len(hang_success)}")
        w("")
        w("family split (official / strict):")
        for f in sorted(fam):
            v = fam[f]
            w(f"  {f:<10} n={v['n']:<5} B={v['b']:<5} ({pct(v['b'], v['n']):>5})  "
              f"C={v['c']:<5} ({pct(v['c'], v['n']):>5})  auditor={v['aud']}")
        w("")
        w(f"re-run slice (in_171, excl. removed) : {len(in171)}")
        w(f"  official predicate               : {len(o171)}/{len(in171)} = {pct(len(o171), len(in171))}")
        w(f"  strict crash                     : {len(s171)}/{len(in171)} = {pct(len(s171), len(in171))}")
        w(f"  of which quota casualties        : {len(cas_in_171)}"
          f"  (official {len(o_cas)}/{len(cas_in_171)} = {pct(len(o_cas), len(cas_in_171))})")
        w(f"  capability denominator           : {len(cap_in_171)}"
          f"  (official {len(o_cap)}/{len(cap_in_171)} = {pct(len(o_cap), len(cap_in_171))},"
          f" strict {len(s_cap)}/{len(cap_in_171)} = {pct(len(s_cap), len(cap_in_171))})")
        w(f"    rows with an actual verdict    : {len(cap_verdict)}"
          f"  (official {len(o_cap_verdict)}/{len(cap_verdict)} = {pct(len(o_cap_verdict), len(cap_verdict))};"
          f" {len(cap_in_171)-len(cap_verdict)} rows have no submission record)")
        w("=" * 64)
        w("[TIER 1] recomputed from the shipped CSV alone")
        w("bridge:")
        w(f"  raw_official=1                  : {bridge['raw_official_1']:,}")
        w(f"  - excluded that were raw=1      : {bridge['excluded_that_were_raw_official_1']}")
        w(f"  = official_success=1            : {bridge['official_success_1']:,}"
          f"  {'OK' if bridge['check'] else 'MISMATCH'}")
        w("set relations:")
        w(f"  |E|={rel['E']}  |D_raw|={rel['D_raw']}  |D_adj|={rel['D_adj']}"
          f"  |E&D_raw|={rel['E_inter_D_raw']}  |E&D_adj|={rel['E_inter_D_adj']}")
        w(f"  raw  inconsistent               : {rel['raw_fwd']} fwd + {rel['raw_rev']} rev = {rel['D_raw']}")
        w(f"  adj  inconsistent               : {rel['adj_fwd']} fwd + {rel['adj_rev']} rev = {rel['D_adj']}")
        w(f"  tainted inside D_raw            : {rel['tainted_in_D_raw']}")
        w("")
        w("[TIER 2] internal consistency check of the shipped any-of table")
        if anyof is None:
            w("final-only evidence              : CSV not found")
        else:
            att = sum(int(r["attempts"]) for r in anyof)
            w(f"  rows / total attempts          : {Lset['L']} / {att}")
            w(f"  of which inside the exclusion  : {Lset['L_inter_E']}")
            w(f"  survives exclusion (|L \\ E|)   : {Lset['L_minus_E']}")
            w("  NOT verified: whether this list is complete (needs poc_records)")
        w("")
        w("[TIER 3] reported values, NOT re-derivable from the package")
        # Deliberately NOT labelled final-only / any-of: `raw_official` is the
        # pre-adjudication official predicate and `raw_claimed` is the run's own
        # self-report. Neither is an any-of count -- any-of would need the full
        # poc_records history, which is not shipped. Earlier revisions mislabelled
        # these two columns, which made a self-report look like an any-of metric.
        w(f"  pre-adjudication official (raw_official=1) : {bridge['raw_official_1']:,}")
        w(f"  run self-report (raw_claimed=1)            : {bridge['raw_claimed_1']:,}")
        w("  final-only / any-of counts                 : NOT DERIVABLE from the package"
          " (need poc_records); the two numbers above are NOT those metrics")
        w("")
        w(f"role split                         : engineer {roles['engineer']}, auditor {roles['auditor']}")
        if discounted:
            w("")
            w(f"discounted (claimed but disproven by the scoring DB): {len(discounted)}")
            for t in discounted[:20]:
                r = recs[t]
                w(f"  {t:<16} vul={r['vul_exit_code'] or '-':>3}  fix={r['fix_exit_code'] or '-':>3}")
            if len(discounted) > 20:
                w(f"  ... and {len(discounted) - 20} more")

    print("\n".join(out))

    # A verifier that always returns 0 is not a verifier. Integrity failures are
    # reported on stdout *and* reflected in the exit status so that a CI-style
    # "did the check pass" question has an answer.
    if integrity_failures:
        print()
        print("VERIFICATION FAILED", file=sys.stderr)
        for f in integrity_failures:
            print("  - " + f, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
