"""P2 T2.1/T2.2:四角色流水线编排骨架。

- intel 前置相位:LOCATE 派发给 intel_analyst(pi 会话),产 intel-brief.md;
- 主循环复用 orchestrator.run_task(worker=PiWorker 已按角色路由/契约提示/预算限额);
- 心跳(≤10s)携带 per-role 状态,覆盖全部角色 worker;
- 角色派发/handoff 已由 PiWorker 落 journal(role_dispatch/handoff 事件)。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.budget import Budget
from agent.contract import TaskType
from agent.orchestrator import AttemptContext
from supervisor.watchdog import Heartbeat


class MultiRoleHarness:
    def __init__(self, worker, store, heartbeat: Heartbeat | None = None):
        self.worker = worker
        self.store = store
        self.heartbeat = heartbeat
        if heartbeat is not None:
            worker.heartbeat = heartbeat

    def run_intel_phase(self, env) -> bool:
        """intel_analyst 前置相位:产 intel-brief.md(kb 检索位在 T2.6 接入 kb-query)。"""
        ctx = AttemptContext(
            task_id=env.task_id, description=env.description,
            repo_manifest=env.context_manifest(), history=[],
            store=self.store, budget=Budget(), inject={},
            artifacts_dir=self.store.dir(env.task_id))
        result = self.worker(TaskType.LOCATE, ctx)
        ok = bool(result.ok) and (self.store.dir(env.task_id) / "intel-brief.md").exists()
        if ok:
            self.store.journal(env.task_id, "commit", {"records": ["NOTE-001(intel-brief.md)"]})
        return ok
