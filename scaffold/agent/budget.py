"""Hard guardrails (the "hook layer" of the reference framework).

Prompt discipline is the first line; these counters are the second and they
cannot be talked around. BudgetExceeded aborts the attempt loop and forces a
FAILED handoff with partial results preserved in the task store.

halt()/halted() implement the reference's sentinel discipline: once the cap is
hit, a .HALTED marker is dropped and EVERY later guard() call refuses, even
from code that does not track rounds (e.g. a fuzz launch about to burn 300s
inside the last round). Denial happens at the harness layer; it does not
depend on the model cooperating.
"""
import time
from dataclasses import dataclass, field
from pathlib import Path


class BudgetExceeded(Exception):
    pass


@dataclass
class Budget:
    max_rounds: int = 8
    max_llm_calls: int = 60
    max_tool_calls: int = 120
    wall_clock_s: int = 1800  # 30 min per task, aligned with the reference "probe slows down" signal

    rounds_used: int = 0
    llm_calls: int = 0
    tool_calls: int = 0
    started_at: float = field(default_factory=time.monotonic)
    sentinel_dir: Path | None = None   # where the .HALTED marker is dropped

    _halt_reason: str = ""

    def consume(self, *, round: int = 0, llm: int = 0, tool: int = 0) -> None:
        self.rounds_used += round
        self.llm_calls += llm
        self.tool_calls += tool
        self.guard()

    def guard(self) -> None:
        if self._halt_reason:
            raise BudgetExceeded(f"halted: {self._halt_reason}")
        if self.rounds_used > self.max_rounds:
            self.halt(f"rounds {self.rounds_used}/{self.max_rounds}")
        elif self.llm_calls > self.max_llm_calls:
            self.halt(f"llm_calls {self.llm_calls}/{self.max_llm_calls}")
        elif self.tool_calls > self.max_tool_calls:
            self.halt(f"tool_calls {self.tool_calls}/{self.max_tool_calls}")
        else:
            elapsed = time.monotonic() - self.started_at
            if elapsed > self.wall_clock_s:
                self.halt(f"wall_clock {int(elapsed)}s/{self.wall_clock_s}s")
        if self._halt_reason:
            raise BudgetExceeded(self._halt_reason)

    def halt(self, reason: str) -> None:
        """Latch the halt and drop the sentinel for observability/cleanup."""
        if self._halt_reason:
            return
        self._halt_reason = reason
        try:
            if self.sentinel_dir is not None:
                p = Path(self.sentinel_dir) / ".HALTED"
                p.write_text(f"{reason}\n{time.time()}\n", encoding="utf-8")
        except OSError:
            pass  # observability only; the latch itself is the enforcement

    def halted(self) -> bool:
        return bool(self._halt_reason)

    def rounds_left(self) -> int:
        try:
            self.guard()
        except BudgetExceeded:
            return 0
        return self.max_rounds - self.rounds_used

    def snapshot(self) -> dict:
        return {
            "rounds": f"{self.rounds_used}/{self.max_rounds}",
            "llm": f"{self.llm_calls}/{self.max_llm_calls}",
            "tools": f"{self.tool_calls}/{self.max_tool_calls}",
            "elapsed_s": int(time.monotonic() - self.started_at),
            "halted": self._halt_reason or None,
        }
