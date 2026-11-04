"""retry-strategist: verdict -> next action decision table.

Encodes two disciplines from the reference framework:
  1. strategy ladder: a failure class exhausts its per-class cap only by
     ROTATING to the next strategy that still has budget, never by closing
     the task early ("untested-but-closable" is the reference's most severe
     field failure; only a fully spent ladder is a legitimate closure)
  2. closure whitelist: a task may end before the round budget only for
     verified / env-suspect / human-input; everything else must keep trying
     while any ladder slot remains

Routing reads TaskState.history only (handoff is display-only).
"""
from dataclasses import dataclass
from typing import Optional

from agent.contract import TaskType, Verdict


@dataclass
class Decision:
    next_task: Optional[TaskType]
    stop: bool = False
    reason: str = ""
    inject: str = ""   # extra context key the worker must receive (e.g. compiler errors)


# verdict -> (strategy, per-class repeat cap, context to inject)
_TABLE = {
    Verdict.COMPILE_ERROR:     (TaskType.CONSTRUCT,    3, "compiler_log"),
    Verdict.NO_TRIGGER:        (TaskType.FUZZ,         2, "last_seed"),   # fuzz the model seed first
    Verdict.WRONG_BUG:         (TaskType.CONSTRUCT,    2, "crash_signature"),
    Verdict.FIX_ALSO_TRIGGERS: (TaskType.HYPOTHESIZE,  2, "both_signatures"),
    Verdict.TIMEOUT:           (TaskType.CONSTRUCT,    2, "timeout_budget"),
    Verdict.FLAKY:             (TaskType.CONSTRUCT,    1, "stability_report"),
    Verdict.INCONCLUSIVE:      (None,                  0, ""),        # env suspect -> stop for env fix
    Verdict.BLOCKED:           (None,                  0, ""),        # human input required
    Verdict.FAILED:            (None,                  0, ""),
    Verdict.VERIFIED:          (None,                  0, ""),        # done
}

# closure whitelist: reasons a task may stop with rounds left. Mirrors the
# reference's "only these may close untested work" rule.
_CLOSURE_WHITELIST = {Verdict.VERIFIED, Verdict.INCONCLUSIVE, Verdict.BLOCKED}

# rotation order when the current class exhausts its cap
_LADDER = [TaskType.HYPOTHESIZE, TaskType.CONSTRUCT, TaskType.FUZZ]


def decide(history: list) -> Decision:
    """history: list of Verdict (oldest first)."""
    if not history:
        return Decision(TaskType.HYPOTHESIZE, reason="cold start")
    if history[-1] == Verdict.VERIFIED:
        return Decision(None, stop=True, reason="verified")

    last = history[-1]
    if last in _CLOSURE_WHITELIST or last == Verdict.FAILED:
        return Decision(None, stop=True, reason=f"{last.value}: not retryable at task level")

    strategy, cap, inject = _TABLE[last]
    repeats = _consecutive(history, last)
    if repeats <= cap:
        return Decision(strategy, reason=f"{last.value} (repeat {repeats}/{cap})", inject=inject)

    # class cap spent -> rotate to the next ladder strategy that still has
    # headroom, instead of declaring the task exhausted
    usage = _strategy_usage(history)
    for alt in _LADDER:
        if alt == strategy:
            continue
        if usage.get(alt, 0) < _class_cap(alt):
            why = f"{last.value} x{repeats}: rotate strategy"
            alt_inject = ""
            for v, (t, _, inj) in _TABLE.items():
                if t == alt and inj:
                    alt_inject = inj
                    break
            return Decision(alt, reason=why, inject=alt_inject)

    return Decision(None, stop=True,
                    reason=f"{last.value} x{repeats}: full strategy ladder spent "
                           f"(hyp/construct/fuzz all at cap)")


def _strategy_usage(history: list) -> dict:
    """How many history entries routed to each strategy (approximation: count
    verdicts whose table strategy is that task type)."""
    usage = {}
    for h in history:
        entry = _TABLE.get(h)
        if entry and entry[0] is not None:
            usage[entry[0]] = usage.get(entry[0], 0) + 1
    return usage


def _class_cap(task_type: TaskType) -> int:
    """Rotation headroom per strategy: total verdicts that may route to it."""
    caps = [cap for t, cap, _ in _TABLE.values() if t == task_type]
    return max(caps) if caps else 0


def _consecutive(history: list, v: Verdict) -> int:
    n = 0
    for h in reversed(history):
        if h == v:
            n += 1
        else:
            break
    return n
