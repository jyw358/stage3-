"""C-line reliability: heartbeat (<=10s interval) + crash recovery.

KPIs covered:
  - heartbeat interval <= 10s        -> Heartbeat (default 5s, threaded)
  - fault recovery <= 120s           -> recover() = detect stale beat + restore snapshot
  - resume without manual reconfig   -> state lives in TaskStore; orchestrator re-enters loop
"""
import json
import threading
import time
from pathlib import Path

from agent.kblite import TaskStore, TaskStatus
from agent.contract import SnapshotNode


class Heartbeat:
    """Writes a heartbeat file that a watchdog (or systemd/K8s probe) can watch.
    The file is the contract: {ts, task_id, phase, budget}. No shared memory."""

    def __init__(self, path: str | Path, interval_s: float = 5.0):
        self.path = Path(path)
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._payload: dict = {}

    def beat(self, **payload) -> None:
        self._payload = {"ts": time.time(), **payload}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def start_background(self, **payload) -> None:
        self.beat(**payload)

        def loop():
            while not self._stop.wait(self.interval_s):
                # P2:重打"最新"载荷(手动 beat 更新过角色状态则随之刷新),非启动时快照
                self.beat(**{**self._payload_kw, **self._payload})

        self._payload_kw = payload
        self._thread = threading.Thread(target=loop, daemon=True, name="heartbeat")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    @staticmethod
    def is_stale(path: str | Path, max_age_s: float = 15.0) -> bool:
        p = Path(path)
        if not p.exists():
            return True
        try:
            ts = json.loads(p.read_text(encoding="utf-8")).get("ts", 0)
        except (json.JSONDecodeError, OSError):
            return True
        return (time.time() - ts) > max_age_s


def recover(store: TaskStore, heartbeat_path: str | Path,
            max_age_s: float = 15.0) -> list:
    """Detect dead agent (stale heartbeat) and resume tasks from snapshots.
    Returns list of {task_id, resumed_from, prior_status}. Idempotent."""
    resumed = []
    if not Heartbeat.is_stale(heartbeat_path, max_age_s):
        return resumed

    for state_file in store.root.glob("*/state.json"):
        task_id = state_file.parent.name
        st = store.load(task_id)
        if st.status not in (TaskStatus.RUNNING, TaskStatus.INTERRUPTED):
            continue
        prior = st.status
        node = store.restore_latest(task_id)
        if node is None:
            # no snapshot yet: re-init in place, journal keeps history
            store.journal(task_id, "recovered_cold", {"prior": prior})
            st.status = TaskStatus.RUNNING
            st.phase = "resumed-cold"
            store.update(st)
            node = "cold"
        resumed.append({"task_id": task_id, "resumed_from": node, "prior_status": prior})
    return resumed


# snapshot node helpers used by the orchestrator
SNAPSHOT_NODES = SnapshotNode
