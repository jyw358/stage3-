"""runner_exec — cybergym-runner submit 的后台执行体。

读 .job 文件,LocalRunner 执行,写 .out(截尾)。路径遏制:job 内 cwd 必须与其所在
任务目录一致,防 spool 目录逃逸。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from plugins.diff_verifier import parse_signature
from plugins.local_runner import LocalRunner

TAIL = 2000


def main(job_path: str) -> int:
    job = json.loads(Path(job_path).read_text(encoding="utf-8"))
    jobs_dir = Path(job_path).resolve().parent
    out_path = jobs_dir / (Path(job_path).stem + ".out")
    try:
        cwd = Path(job["cwd"]).resolve()
        if cwd.resolve() != jobs_dir.parent.parent.resolve():
            raise RuntimeError("job cwd escaping task dir")
        os.chdir(cwd)                 # 任务目录内解析相对 binary/poc 路径
        runner = LocalRunner()
        oc = runner.run(job["binary"], job["poc"], timeout_s=job.get("timeout_s", 10))
        sig = parse_signature(oc) or (oc.signature if oc.signature else None)
        payload = {
            "task_id": job["task_id"], "state": "done",
            "image": job["image"],
            "exit_code": oc.returncode, "timed_out": oc.timed_out,
            "stdout_tail": oc.stdout[-TAIL:], "stderr_tail": oc.stderr[-TAIL:],
            "signature": list(sig) if sig else None,
        }
    except Exception as e:  # noqa: BLE001 — 后台体只落盘不抛
        payload = {"task_id": job.get("task_id"), "state": "error", "error": str(e)}
    tmp = out_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    tmp.replace(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
