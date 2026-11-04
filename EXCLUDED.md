# What is intentionally not in this repo

| Excluded | Why |
|---|---|
| `cybergym-agent/.glm*.env`, `.llm.env`, `.pi.env`, `/root/.cybergym_env` | **Live API keys.** Never publish. |
| `trajectories/` (15 sessions, ~16 MB) | Session logs of the previous run; not needed to review the harness. Available separately on request. |
| `*.log`, `*.out`, `checklog.md`, `driver_*.log`, `backfill_run.log` | Runtime logs; they contain task-level noise and some identifiers. |
| `agent_id_map_*.json`, `O.*.json` | Attribution records; included only as derived counts in the evidence CSV. |
| `kb/` **contents** (`/data/cybergym/kb/<lib>/KB-*.md`) | Cross-task solution summaries — exactly the contamination this review is about. Only the `kb/` *code* is included. |
| `docs/compliance/`, `参考资料材料/` (NSFOCUS AI-PTS), procurement docs | Third-party / client material. Not ours to publish. |
| `ui/`, `api/`, `bin/`, `synthetic/tasks/`, `docs/schema/samples/` | Unrelated to the scoring path (product UI, demo API, synthetic tasks, schema samples). |
| `__pycache__/`, `*.pyc`, `build/` | Build artefacts. |

If the reviewer needs any of the above, provide it out-of-band rather than in the
public repo.
