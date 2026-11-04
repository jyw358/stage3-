"""Run one real CyberGym task end-to-end with the LLM worker.

Env required:
  CYBERGYM_API_KEY   PoC server key (from ~/work/cybergym/.env)
  LLM_API_KEY        model provider key (e.g. DeepSeek)
Optional:
  LLM_BASE_URL  (default https://api.deepseek.com/v1)
  LLM_MODEL     (default deepseek-chat)

Example (on the server):
  cd ~/work/cybergym-agent && source ~/work/cybergym/.venv/bin/activate
  set -a && . ~/work/cybergym/.env && set +a && export LLM_API_KEY=sk-...
  python scripts/run_llm_task.py --task-dir ~/work/cybergym/task_368 \
      --task-id arvo:368 --max-rounds 8
"""
import argparse
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.budget import Budget, BudgetExceeded
from agent.contract import TaskType, Verdict
from agent.kblite import TaskStore
from agent.llm import OpenAICompatClient
from agent.llm_worker import LLMWorker
from agent.orchestrator import run_task
from plugins.cybergym_runner import CyberGymRunner
from plugins.env_manager import TaskEnv
from plugins.fuzz_local import fuzz_one, parse_fuzz_stats, repro_single
from plugins.diff_verifier import is_memory_crash, parse_signature
from supervisor.watchdog import Heartbeat


class _CtxWithFuzzStats:
    """Forward AttemptContext, merging fuzz exploration stats into inject."""

    def __init__(self, ctx, fuzz_stats: str):
        self._ctx = ctx
        self._fuzz_stats = fuzz_stats

    def __getattr__(self, name):
        return getattr(self._ctx, name)

    @property
    def inject(self):
        merged = dict(self._ctx.inject or {})
        if self._fuzz_stats:
            merged["fuzz_stats"] = self._fuzz_stats
        return merged


class WorkerWithFuzz:
    """LLM worker + local directed fuzzing: FUZZ rounds run libFuzzer on the
    model's seed against the vulnerable build (no LLM cost)."""

    def __init__(self, llm_worker, task_id: str, task_dir: str,
                 base_seconds: int | None = None):
        self.llm = llm_worker
        self.task_id = task_id
        self.task_dir = Path(task_dir)
        # FUZZ_BASE_SECONDS: escalate ladder start (30 default; 300 for the
        # budget scale-up experiment -- fuzz hits produced ~every solve so far)
        self.base_seconds = base_seconds or int(os.environ.get(
            "FUZZ_BASE_SECONDS", "30"))
        self.fuzz_runs = 0
        self.last_fuzz_stats = ""

    def __call__(self, task_type, ctx):
        if task_type == TaskType.FUZZ:
            # harness-layer denial (reference sentinel discipline): if the wall
            # clock is already spent, do not burn another 300-600s fuzz round
            try:
                ctx.budget.guard()
            except BudgetExceeded as e:
                return type("R", (), {"ok": False, "poc_path": None,
                                      "hypothesis": "",
                                      "note": f"halted before fuzz: {e}"})()
            self.fuzz_runs += 1
            seconds = self.base_seconds * self.fuzz_runs   # escalate: 30s, 60s, ...
            seeds = [p for p in [self.task_dir / "poc.bin"] if p.exists()]
            # v2: central corpus goes straight into the fuzz seed pool
            # (bypasses the model entirely -- diversity preserved both sides)
            try:
                from plugins.corpus_store import CENTRAL
                central = CENTRAL / str(self.task_id).replace(":", "_")
                if central.exists():
                    seeds += [p for p in sorted(central.iterdir(),
                                                key=lambda q: q.stat().st_size,
                                                reverse=True)[:6]]
            except Exception:
                pass
            # reuse previous fuzz crashes as seeds too (they may mutate further)
            seeds += sorted((self.task_dir / "fuzz-out").glob("crash-*"))[:2] \
                if (self.task_dir / "fuzz-out").exists() else []
            crash, tail = fuzz_one(self.task_id, seeds,
                                   self.task_dir / "fuzz-out", seconds=seconds)
            self.last_fuzz_stats = parse_fuzz_stats(tail)
            note = (tail or "")[-800:]
            if crash:
                # artifact triage: libFuzzer also writes crash-* for the
                # exit()-rejection path; only a replayed MEMORY crash is a PoC
                out = repro_single(self.task_id, str(crash))
                if is_memory_crash(parse_signature(out)):
                    kept = self.task_dir / f"fuzz-crash-{self.fuzz_runs}.bin"
                    kept.write_bytes(crash.read_bytes())
                    print(f"[*] FUZZ hit (memory crash, triaged): "
                          f"{crash.name} ({seconds}s)", flush=True)
                    return type("R", (), {"ok": True, "poc_path": str(kept),
                                          "hypothesis": "", "note": note})()
                # fake positive: keep as corpus seed, do not waste a verify round
                shutil.copyfile(crash, self.task_dir / "fuzz-out" / "corpus" /
                                f"fake-{self.fuzz_runs}")
                self.last_fuzz_stats += (
                    "\nNOTE: last fuzz artifact was only an exit()-rejection, "
                    "NOT a memory crash -- craft seeds that reach memory bugs.")
                print(f"[*] FUZZ artifact triaged out (exit-path, not memory)",
                      flush=True)
            print(f"[*] FUZZ clean ({seconds}s)", flush=True)
            return type("R", (), {"ok": False, "poc_path": None, "hypothesis": "",
                                  "note": f"no crash in {seconds}s fuzzing\n{note}"})()
        if task_type == TaskType.CONSTRUCT and self.last_fuzz_stats:
            return self.llm(task_type, _CtxWithFuzzStats(ctx, self.last_fuzz_stats))
        return self.llm(task_type, ctx)


def run_one(task_dir: str, task_id: str, server: str, cg_key: str, llm_key: str,
            model: str, base_url: str, max_rounds: int, tasks_root: str,
            quiet: bool = False) -> dict:
    """Run one task end-to-end; returns a summary dict (used by CLI and batch)."""
    import time as _t
    t0 = _t.time()
    runner = CyberGymRunner(server, task_dir, api_key=cg_key)
    env = TaskEnv(
        task_id=task_id, workdir=Path(task_dir),
        vul_image="vul", fix_image="fix",
        description=(Path(task_dir) / "description.txt").read_text(encoding="utf-8", errors="ignore"),
    )
    client = OpenAICompatClient(base_url, llm_key, model)
    hypo_model = os.environ.get("LLM_HYPO_MODEL", "")
    hypo_client = None
    if hypo_model and hypo_model != model:
        hypo_url = os.environ.get("LLM_HYPO_BASE_URL", base_url)
        hypo_key = os.environ.get("LLM_HYPO_API_KEY", llm_key)
        hypo_client = OpenAICompatClient(hypo_url, hypo_key, hypo_model)
    worker = WorkerWithFuzz(LLMWorker(client, task_dir, hypo_client=hypo_client),
                            task_id, task_dir)
    store = TaskStore(tasks_root)
    hb = Heartbeat(Path(tasks_root) / "heartbeat.json", interval_s=5)
    if not quiet:
        print(f"[*] task={task_id} model={model} rounds<={max_rounds}", flush=True)
    verdict = run_task(env, worker, store, runner, heartbeat=hb,
                       budget=Budget(max_rounds=max_rounds,
                                     wall_clock_s=int(os.environ.get(
                                         "WALL_CLOCK_S", "1800")),
                                     sentinel_dir=Path(task_dir)))
    st = store.load(task_id)

    row = {
        "task_id": task_id,
        "verdict": verdict.value,
        "status": st.status,
        "rounds": st.rounds_used,
        "attempts": st.attempts,
        "history": [h["verdict"] for h in st.history],
        "llm_calls": client.usage.calls,
        "prompt_tokens": client.usage.prompt_tokens,
        "completion_tokens": client.usage.completion_tokens,
        "elapsed_s": round(_t.time() - t0, 1),
    }
    try:
        recs = runner.query_poc(original_task_id=task_id)
        finals = [r for r in recs if r.get("vul_exit_code") not in (0, 300, None)]
        if finals:
            best = finals[-1]
            row["final_poc"] = {
                "poc_id": best.get("poc_id"),
                "vul_exit_code": best.get("vul_exit_code"),
                "fix_exit_code": best.get("fix_exit_code"),
            }
        row["official_success"] = CyberGymRunner.official_success(recs)
    except Exception as e:
        row["query_error"] = str(e)
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-dir", required=True)
    ap.add_argument("--task-id", required=True, help="original id, e.g. arvo:368")
    ap.add_argument("--server", default="http://172.17.0.1:8666")
    ap.add_argument("--max-rounds", type=int, default=8)
    ap.add_argument("--tasks-root", default="/data/cybergym/agent-tasks")
    ap.add_argument("--model", default=os.environ.get("LLM_MODEL", "deepseek-chat"))
    ap.add_argument("--base-url", default=os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1"))
    args = ap.parse_args()

    cg_key = os.environ.get("CYBERGYM_API_KEY")
    llm_key = os.environ.get("LLM_API_KEY")
    if not cg_key or not llm_key:
        print("[!] need CYBERGYM_API_KEY and LLM_API_KEY in env", file=sys.stderr)
        return 2

    runner = CyberGymRunner(args.server, args.task_dir, api_key=cg_key)
    env = TaskEnv(
        task_id=args.task_id, workdir=Path(args.task_dir),
        vul_image="vul", fix_image="fix",
        description=(Path(args.task_dir) / "description.txt").read_text(encoding="utf-8", errors="ignore"),
    )
    client = OpenAICompatClient(args.base_url, llm_key, args.model)
    worker = LLMWorker(client, args.task_dir)

    store = TaskStore(args.tasks_root)
    hb = Heartbeat(Path(args.tasks_root) / "heartbeat.json", interval_s=5)
    print(f"[*] task={args.task_id} model={args.model} rounds<={args.max_rounds}")
    verdict = run_task(env, worker, store, runner, heartbeat=hb,
                       budget=Budget(max_rounds=args.max_rounds))

    st = store.load(args.task_id)
    print("\n=== result ===")
    print(f"verdict: {verdict.value}   status: {st.status}")
    print(f"rounds:  {st.rounds_used}, attempts: {st.attempts}")
    print(f"history: {[h['verdict'] for h in st.history]}")
    print(f"llm:     {client.usage.calls} calls, "
          f"{client.usage.prompt_tokens}p+{client.usage.completion_tokens}c tokens")

    if st.history:
        print(f"\npoc.db records ({args.task_id}):")
        try:
            for rec in runner.query_poc(original_task_id=args.task_id):
                print("   ", {k: rec.get(k) for k in
                              ("poc_id", "poc_length", "vul_exit_code", "fix_exit_code")})
        except Exception as e:
            print("    query failed:", e)
    return 0 if verdict == Verdict.VERIFIED else 1


if __name__ == "__main__":
    raise SystemExit(main())
