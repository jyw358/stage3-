# stage3 harness — review snapshot

This repository is a **read-only snapshot of the Stage-3 harness** used to run
CyberGym Level 1 (1,507 tasks), published so an external reviewer can audit it
**before a re-run**.

It is not a product repo: there is no build, no CI, no tests to run. The point is
to read the code that produces the score.

## Layout

| Path | What it is |
|---|---|
| `runner/` | The task driver and workspace generator. **Start here.** |
| `runner/history/` | `.bak-*` versions from 2026-10-21/22/25 — useful for diffing what changed and why |
| `plugins/` | Submission client (`cybergym_runner.py`) and local runner |
| `scaffold/` | Agent skeleton: `agent/` (contract / orchestrator / budget / retry), `agents/`, `roles/`, `supervisor/`, `kb/` |
| `scoring/` | Post-run scoring, fix-side backfill, dual-metric export, workspace seal |
| `evidence/` | The 1,507-row exit-code table, `recount.py`, the official roster, the intel inventory |
| `docs/` | Two hand-off documents: what changed on 2026-10-21, and a gate-verification report |

## Read in this order

1. `runner/run_agent_task.sh` — per-task driver: workspace, budget, mission, submit, second pass.
2. `runner/make_agent_ws.py` — workspace generator: what files the agent gets, and the tool set.
3. `runner/stage2.sh` — the earlier multi-wave driver; **also writes `reference-intel.md`**.
4. `scoring/score_all.sh` — how `official_success` is produced.
5. `plugins/cybergym_runner.py` — what is sent to the submission server, and what comes back.
6. `scoring/backfill_fix_side.sh` — the fix-side backfill (the weakest link in the last submission).

## Notes on paths

The code is **verbatim from the campaign host**, so absolute paths such as
`/home/naco/...`, `/root/...`, `/data/cybergym/...` and the docker-bridge endpoint
`http://172.17.0.1:8666` are present. They are not rewritten: rewriting them would
make the review diverge from what actually ran. No credentials are included; the
`.env` files were removed.

## What is **not** here

See `EXCLUDED.md`. In short: credentials (`.env`), 16 MB of session trajectories,
runtime logs, client/compliance documents, and the cross-task knowledge-base
contents.

## Evidence files

`evidence/final_submission_exitcodes_stage3.csv` is the 1,507-row table from the
last submission. `evidence/recount.py` recomputes every headline figure from it
(needs `pip install openpyxl` for the roster). Treat the numbers as the **previous**
run, not as ground truth.
