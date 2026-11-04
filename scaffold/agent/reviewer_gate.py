"""S3: 评审层与偏离纠正——Reviewer 角色的编排器侧门控。

集成点:orchestrator.run_task() 在每轮 verdict 后调用 evaluate(),
偏离时触发回退重规划(最大重试次数+降级策略)。

独立于 diff_verifier(系统闸门:差分验证);
Reviewer 是 LLM 侧质量评估(格式合规/逻辑一致/结果合理)。
"""
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class DeviationType(Enum):
    FORMAT = "format"           # 输出格式不合规(缺字段/类型错)
    LOGIC = "logic"             # 逻辑不一致(结论与证据矛盾)
    PLAUSIBILITY = "plausibility"  # 结果不合理(如"所有文件都有漏洞")
    SCOPE = "scope"             # 超出任务范围
    NONE = "none"               # 无偏离


@dataclass
class ReviewResult:
    deviation: DeviationType
    severity: str  # "low" / "medium" / "high"
    detail: str = ""
    should_rollback: bool = False
    action: str = ""  # "replan" / "retry" / "continue" / "degrade"


class ReviewerGate:
    """编排器侧评审门——每轮 verdict 后质量检查。"""

    def __init__(self, max_retries: int = 3, degrade_after: int = 2):
        self.max_retries = max_retries
        self.degrade_after = degrade_after
        self.consecutive_deviations = 0
        self.total_reviews = 0

    def evaluate(self, verdict: str, detail: str, attempt_output: dict) -> ReviewResult:
        """评估一次执行输出;返回 ReviewResult 决定下一步动作。"""
        self.total_reviews += 1
        deviation = self._classify(verdict, detail, attempt_output)

        if deviation == DeviationType.NONE:
            self.consecutive_deviations = 0
            return ReviewResult(deviation, "none", "ok", False, "continue")

        self.consecutive_deviations += 1
        should_rollback = self.consecutive_deviations >= self.degrade_after
        action = self._decide_action(deviation, should_rollback)
        return ReviewResult(
            deviation=deviation,
            severity=self._severity(deviation, self.consecutive_deviations),
            detail=f"[review #{self.total_reviews}] {detail[:200]}",
            should_rollback=should_rollback,
            action=action,
        )

    def _classify(self, verdict: str, detail: str, output: dict) -> DeviationType:
        """启发式分类(可替换为 LLM reviewer 角色)。"""
        if not output:
            return DeviationType.FORMAT
        if verdict == "verified" and not output.get("poc_path"):
            return DeviationType.LOGIC
        if verdict in ("blocked", "timeout") and self.consecutive_deviations >= 2:
            return DeviationType.PLAUSIBILITY
        return DeviationType.NONE

    def _decide_action(self, deviation: DeviationType, rollback: bool) -> str:
        if self.consecutive_deviations >= self.max_retries:
            return "degrade"
        if rollback:
            return "replan"
        return "retry"

    @staticmethod
    def _severity(deviation: DeviationType, count: int) -> str:
        if count >= 3:
            return "high"
        if deviation in (DeviationType.LOGIC, DeviationType.PLAUSIBILITY):
            return "medium"
        return "low"
