"""Orchestrator: per-task attempt loop.

Contract with workers (LLM side) and plugins (tool side):
  - workers produce hypotheses + PoC candidates; they never see verify results
    as authority -- the diff-verifier verdict is the only gate (separation of duties)
  - routing is driven by TaskState.history via retry.decide(), never by prose
  - every key transition is snapshotted and journalled; the loop is restartable
    at any point (supervisor.recover -> orchestrator.run re-entry)
"""
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

from agent import retry
from agent.budget import Budget, BudgetExceeded
from agent.contract import SnapshotNode, TaskType, Verdict
from agent.kblite import TaskStore, TaskStatus
from plugins.diff_verifier import verify_ex
from supervisor.watchdog import Heartbeat


class WorkerFn(Protocol):
    """LLM-backed worker. Receives full context slice; returns a candidate PoC path
    (or None -> worker-side BLOCKED/FAILED with `note`). Real impl: dsh subagent
    driven by agents/vuln_analyst.md; dryrun impl in run_task.py."""

    def __call__(self, task_type: TaskType, ctx: "AttemptContext") -> "AttemptResult": ...


@dataclass
class AttemptContext:
    task_id: str
    description: str
    repo_manifest: dict
    history: list            # verdict values so far
    store: TaskStore
    budget: Budget
    inject: dict             # retry-strategist context keys (compiler_log etc.)
    artifacts_dir: Path
    hypothesis: str = ""     # committed hypothesis the construct must implement


@dataclass
class AttemptResult:
    ok: bool
    poc_path: Optional[str] = None
    hypothesis: str = ""     # required when task_type == HYPOTHESIZE
    note: str = ""


def _format_feedback(verdict: Verdict, ev: dict) -> str:
    """Turn verifier evidence into text the next construct round can act on."""
    lines = [f"last attempt verdict: {verdict.value}",
             f"vul_exit={ev.get('vul_exit')} fix_exit={ev.get('fix_exit')} "
             f"vul_sig={ev.get('vul_sig')} fix_sig={ev.get('fix_sig')}"]
    if ev.get("stability_hits") is not None:
        lines.append(f"stability_hits={ev['stability_hits']}")
    vul_out = (ev.get("vul_output") or "").strip()
    if vul_out:
        lines.append("--- vulnerable build output (tail) ---\n" + vul_out)
    return "\n".join(lines)


def run_task(env, worker: WorkerFn, store: TaskStore,
             runner, heartbeat: Optional[Heartbeat] = None,
             expected_type: Optional[str] = None,
             budget: Optional[Budget] = None,
             resume: bool = False) -> Verdict:
    task_id = env.task_id
    st = store.init_task(task_id)   # 已有状态则加载(续跑入口)
    budget = budget or Budget()
    if resume:
        # T4.5(计划 v3.3.1):三种恢复之"人工/熔断续跑"——状态回滚后从这里重入循环。
        # 预算语义:max_rounds 为总轮次上限,rounds_used 从既有状态续接(剩余=总-已用)。
        if st.status == TaskStatus.VERIFIED:
            store.journal(task_id, "restored", {"skipped": "already verified"})
            return Verdict.VERIFIED
        budget.rounds_used = max(budget.rounds_used, st.rounds_used)
        st.status = TaskStatus.RUNNING
        store.update(st, phase=f"resumed@round-{st.rounds_used}")
        store.journal(task_id, "restored", {
            "rounds_used": st.rounds_used,
            "history": [h["verdict"] for h in st.history]})
    hb_payload = {"task_id": task_id, "phase": "start", "budget": budget.snapshot()}
    if heartbeat:
        heartbeat.start_background(**hb_payload)

    final: Verdict = Verdict.FAILED
    feedback: str = ""    # real execution data from the last attempt, fed forward
    try:
        while budget.rounds_left() > 0:
            committed_hyps = st.id_counters["HYP"]
            if committed_hyps > st.attempts:
                # a committed hypothesis has not been attempted yet -> construct against it
                decision = type("D", (), {
                    "next_task": TaskType.CONSTRUCT, "stop": False,
                    "reason": "pending hypothesis", "inject": ""})()
            else:
                decision = retry.decide([Verdict(h["verdict"]) for h in st.history])
            hypothesis_id = f"HYP-{committed_hyps:03d}" if committed_hyps else None
            if decision.stop and st.history:
                store.journal(task_id, "closure", {"reason": decision.reason})
                final = Verdict(st.history[-1]["verdict"])
                break

            budget.consume(round=1)
            st.rounds_used = budget.rounds_used
            store.update(st, phase=f"round-{budget.rounds_used}:{decision.next_task.value}")

            ctx = AttemptContext(
                task_id=task_id, description=env.description,
                repo_manifest=env.context_manifest(),
                history=[h["verdict"] for h in st.history],
                store=store, budget=budget,
                inject={"last_attempt_feedback": feedback} if feedback else {},
                artifacts_dir=store.dir(task_id),
                hypothesis=(st.last_hypothesis or "")[:4000],
            )
            attempt = worker(decision.next_task, ctx)   # budget.guard() inside worker tool calls
            budget.consume(llm=0 if decision.next_task == TaskType.FUZZ else 1)

            if decision.next_task == TaskType.HYPOTHESIZE and attempt.ok:
                store.commit(task_id, [{
                    "kind": "HYP", "placeholder": "HYP-1",
                    "body": attempt.hypothesis or attempt.note,
                }])
                store.snapshot(task_id, SnapshotNode.HYPOTHESIS_FORMED)
                st = store.load(task_id)   # refresh counters
                st.last_hypothesis = (attempt.hypothesis or attempt.note)[:4000]
                store.update(st)
                continue

            if not attempt.ok or not attempt.poc_path:
                # construct failure -> COMPILE_ERROR; fuzz exhaustion -> NO_TRIGGER
                # (the seed was searched, move on); anything else is BLOCKED
                if decision.next_task == TaskType.CONSTRUCT:
                    v = Verdict.COMPILE_ERROR
                elif decision.next_task == TaskType.FUZZ:
                    v = Verdict.NO_TRIGGER
                else:
                    v = Verdict.BLOCKED
                feedback = f"last {decision.next_task.value} failed:\n{(attempt.note or '')[-1200:]}"
                store.record_verdict(task_id, v, detail=(attempt.note or "")[:800])
                st = store.load(task_id)
                continue

            verdict, ev = verify_ex(runner, env, attempt.poc_path, expected_type=expected_type)
            feedback = _format_feedback(verdict, ev)
            store.record_verdict(task_id, verdict, detail=f"round-{budget.rounds_used}")
            store.journal(task_id, "attempt_evidence", {"round": budget.rounds_used, **{
                k: v for k, v in ev.items() if k in ("vul_exit", "fix_exit", "vul_sig", "fix_sig", "stability_hits")}})
            st = store.load(task_id)
            st.attempts += 1
            st.last_poc = attempt.poc_path
            store.update(st)
            store.snapshot(task_id, SnapshotNode.POC_COMPILED if verdict != Verdict.COMPILE_ERROR
                           else SnapshotNode.FIRST_RUN_DONE)
            store.snapshot(task_id, SnapshotNode.FIRST_RUN_DONE)

            if verdict == Verdict.VERIFIED:
                store.snapshot(task_id, SnapshotNode.VERIFICATION_PASSED)
                store.snapshot(task_id, SnapshotNode.SUBMITTED)   # submit.sh call is a TODO at integration
                final = verdict
                break
        else:
            final = Verdict(st.history[-1]["verdict"]) if st.history else Verdict.FAILED
            st.status = TaskStatus.EXHAUSTED
            store.update(st)
    except BudgetExceeded as e:
        store.journal(task_id, "budget_exceeded", {"error": str(e)})
        st.status = TaskStatus.EXHAUSTED
        store.update(st)
        final = Verdict.FAILED
    finally:
        if heartbeat:
            heartbeat.beat(task_id=task_id, phase=f"done:{final.value}",
                           budget=budget.snapshot())
            heartbeat.stop()
    return final
