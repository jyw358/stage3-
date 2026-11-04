"""kb-lite: per-task working memory.

Stripped-down version of the reference stigmergy kb. Rules that survive:
  - "if it is not persisted, it did not happen" -> append-only journal
  - placeholder IDs are exchanged for real IDs only at commit (single writer)
  - record/ (evidence) is immutable; attempts archive, never delete

Layout per task:
  <root>/<task_id>/
    state.json        mutable status/counters
    journal.jsonl     append-only events (the truth)
    hypotheses.md     committed hypotheses (real ids)
    attempts/         one md per attempt (what was tried, why it failed)
    evidence/         immutable evidence files (real ids assigned at commit)
    snapshots/        full state copies at the 5 key nodes
"""
import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .contract import SnapshotNode, Verdict


class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    INTERRUPTED = "interrupted"
    VERIFIED = "verified"
    EXHAUSTED = "exhausted"      # budget/rounds spent without success
    BLOCKED = "blocked"


@dataclass
class TaskState:
    task_id: str
    status: str = TaskStatus.PENDING
    phase: str = ""                     # free-form progress note for heartbeat
    rounds_used: int = 0
    attempts: int = 0
    id_counters: dict = field(default_factory=lambda: {"EVI": 0, "HYP": 0, "ATT": 0})
    history: list = field(default_factory=list)   # verifier verdicts, oldest first
    last_hypothesis: Optional[str] = None          # committed hypothesis fed to construct
    last_poc: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class TaskStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # ---------- paths ----------
    def dir(self, task_id: str) -> Path:
        safe = "".join(c if c not in ':*?"<>|' else "_" for c in task_id)
        safe = safe.replace("..", "_")          # no traversal, ever
        return self.root / safe

    def _assert_inside_root(self, p: Path) -> None:
        """Deletion guard: rmtree/copy targets must resolve inside the store root."""
        try:
            p.resolve().relative_to(self.root.resolve())
        except ValueError:
            raise RuntimeError(f"refusing to touch path outside store root: {p}")

    def _state_path(self, task_id: str) -> Path:
        return self.dir(task_id) / "state.json"

    def _journal_path(self, task_id: str) -> Path:
        return self.dir(task_id) / "journal.jsonl"

    # ---------- lifecycle ----------
    def init_task(self, task_id: str) -> TaskState:
        d = self.dir(task_id)
        if self._state_path(task_id).exists():
            return self.load(task_id)
        d.mkdir(parents=True, exist_ok=True)
        (d / "attempts").mkdir(exist_ok=True)
        (d / "evidence").mkdir(exist_ok=True)
        (d / "snapshots").mkdir(exist_ok=True)
        (d / "hypotheses.md").write_text("# Hypotheses\n", encoding="utf-8")
        st = TaskState(task_id=task_id, status=TaskStatus.RUNNING, phase="initialized")
        self._save(st)
        self.journal(task_id, "task_init", {})
        return st

    def load(self, task_id: str) -> TaskState:
        data = json.loads(self._state_path(task_id).read_text(encoding="utf-8"))
        return TaskState(**data)

    def _save(self, st: TaskState) -> None:
        st.updated_at = time.time()
        self.dir(st.task_id).mkdir(parents=True, exist_ok=True)
        self._state_path(st.task_id).write_text(
            json.dumps(asdict(st), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def update(self, st: TaskState, phase: str = "") -> None:
        if phase:
            st.phase = phase
        self._save(st)

    # ---------- journal (append-only) ----------
    def journal(self, task_id: str, event: str, payload: dict) -> None:
        line = json.dumps(
            {"ts": time.time(), "event": event, **payload}, ensure_ascii=False
        )
        with self._journal_path(task_id).open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def journal_tail(self, task_id: str, n: int = 50) -> list:
        p = self._journal_path(task_id)
        if not p.exists():
            return []
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()[-n:] if x]

    # ---------- placeholder -> real ID commit (single writer) ----------
    def commit(self, task_id: str, records: list) -> list:
        """records: [{'kind': 'EVI'|'HYP'|'ATT', 'placeholder': 'EVI-1', 'body': str, 'path': str?}]
        Returns the same records with real IDs filled in. Assignment happens here only."""
        st = self.load(task_id)
        out = []
        for rec in records:
            kind = rec["kind"]
            if kind not in st.id_counters:
                raise ValueError(f"unknown record kind {kind}")
            st.id_counters[kind] += 1
            real_id = f"{kind}-{st.id_counters[kind]:03d}"
            self._persist_record(task_id, real_id, rec)
            out.append({**rec, "id": real_id})
        self._save(st)
        self.journal(task_id, "commit", {"records": [r["id"] for r in out]})
        return out

    def _persist_record(self, task_id: str, real_id: str, rec: dict) -> None:
        if rec["kind"] == "HYP":
            with (self.dir(task_id) / "hypotheses.md").open("a", encoding="utf-8") as f:
                f.write(f"\n## {real_id}\n{rec['body']}\n")
        elif rec["kind"] == "ATT":
            (self.dir(task_id) / "attempts" / f"{real_id}.md").write_text(
                rec["body"], encoding="utf-8"
            )
        elif rec["kind"] == "EVI":
            dest = self.dir(task_id) / "evidence" / f"{real_id}{Path(rec.get('path', '.txt')).suffix}"
            shutil.copyfile(rec["path"], dest)

    # ---------- verdict history ----------
    def record_verdict(self, task_id: str, verdict: Verdict, detail: str = "") -> None:
        st = self.load(task_id)
        st.history.append({"verdict": verdict.value, "detail": detail, "ts": time.time()})
        if verdict == Verdict.VERIFIED:
            st.status = TaskStatus.VERIFIED
        self._save(st)
        self.journal(task_id, "verdict", {"verdict": verdict.value, "detail": detail})

    # ---------- snapshots (KPI: 5 key nodes; T2.4: checkpoint 命名对齐 LangGraph) ----------
    def snapshot(self, task_id: str, node: SnapshotNode) -> Path:
        st = self.load(task_id)
        snap_dir = self.dir(task_id) / "snapshots" / node.value
        self._assert_inside_root(snap_dir)      # deletion guard before rmtree
        prev_seq = 0
        cp_file = snap_dir / "checkpoint.json"
        if cp_file.exists():
            try:
                prev_seq = int(json.loads(cp_file.read_text(encoding="utf-8")).get("seq", 0))
            except (json.JSONDecodeError, OSError):
                prev_seq = 0
        journal_offset = 0
        if self._journal_path(task_id).exists():
            journal_offset = sum(1 for _ in self._journal_path(task_id).open(encoding="utf-8"))
        if snap_dir.exists():
            shutil.rmtree(snap_dir)
        snap_dir.mkdir(parents=True)
        seq = prev_seq + 1
        run_id = f"{task_id}#{int(st.created_at)}"
        checkpoint_id = f"snap:{run_id}:{node.value}:{seq}"
        (snap_dir / "checkpoint.json").write_text(json.dumps({
            "checkpoint_id": checkpoint_id, "run_id": run_id, "node": node.value,
            "seq": seq, "journal_offset": journal_offset,
            "created_at": time.time()}, ensure_ascii=False), encoding="utf-8")
        shutil.copyfile(self._state_path(task_id), snap_dir / "state.json")
        if self._journal_path(task_id).exists():
            shutil.copyfile(self._journal_path(task_id), snap_dir / "journal.jsonl")
        self.journal(task_id, "snapshot",
                     {"node": node.value, "checkpoint_id": checkpoint_id, "seq": seq})
        return snap_dir

    def checkpoint_of(self, task_id: str, node: SnapshotNode) -> str | None:
        """读取某节点当前 checkpoint_id(T2.4:恢复面板/审计直接消费)。"""
        cp = self.dir(task_id) / "snapshots" / node.value / "checkpoint.json"
        if not cp.exists():
            return None
        try:
            return json.loads(cp.read_text(encoding="utf-8")).get("checkpoint_id")
        except (json.JSONDecodeError, OSError):
            return None

    def restore_from(self, task_id: str, node: SnapshotNode) -> Optional[SnapshotNode]:
        """T4.5 人工恢复:从指定节点回退(面板选 checkpoint 用),与 restore_latest 同语义。"""
        snap = self.dir(task_id) / "snapshots" / node.value
        if not (snap / "state.json").exists():
            return None
        st = TaskState(**json.loads((snap / "state.json").read_text(encoding="utf-8")))
        st.status = TaskStatus.RUNNING
        st.phase = f"resumed-from:{node.value}"
        self._save(st)
        self.journal(task_id, "restored", {"node": node.value, "manual": True})
        return node

    def restore_latest(self, task_id: str) -> Optional[SnapshotNode]:
        """Restore state from the newest snapshot; mark task RUNNING again."""
        snaps_root = self.dir(task_id) / "snapshots"
        if not snaps_root.exists() or not any(snaps_root.iterdir()):
            return None
        order = [n.value for n in SnapshotNode]
        latest = sorted(
            (d for d in snaps_root.iterdir() if d.is_dir()),
            key=lambda d: order.index(d.name) if d.name in order else -1,
        )[-1]
        st = TaskState(**json.loads((latest / "state.json").read_text(encoding="utf-8")))
        st.status = TaskStatus.RUNNING
        st.phase = f"resumed-from:{latest.name}"
        self._save(st)
        self.journal(task_id, "restored", {"node": latest.name})
        return SnapshotNode(latest.name)
