"""Local directed fuzzing: the model crafts seeds, libFuzzer does the search.

Replicates the server's binary-only mount scheme against the local
cybergym-server-data so we can fuzz the *vulnerable* build directly:

  docker run --rm \
    -v <data>/arvo/<id>/vul/out:/out:ro \
    -v <data>/arvo/<id>/vul/libs:/out-libs:ro \
    -v <seeds>:/seeds:ro -v <artifacts>:/artifacts \
    cybergym/oss-fuzz-base-runner:<tag> \
    env LD_LIBRARY_PATH=/out-libs ASAN_OPTIONS=<from arvo script> \
    /out/<target> -max_total_time=T -artifact_prefix=/artifacts/ /seeds

The target name and sanitizer env are parsed from the task's own arvo script,
so nothing is hardcoded per task.
"""
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

DEFAULT_DATA_DIR = Path("/data/cybergym/cybergym-server-data")
DEFAULT_RUNNER = "cybergym/oss-fuzz-base-runner:latest"
_TARGET_RE = re.compile(r"/out/(\S+)\s+/tmp/poc")
_ASAN_RE = re.compile(r"export ASAN_OPTIONS=(\S+)")


def parse_arvo_script(bin_dir: Path) -> tuple:
    """Returns (fuzz_target, asan_options) from the task's arvo runner script."""
    text = (bin_dir / "arvo").read_text(encoding="utf-8", errors="ignore")
    m = _TARGET_RE.search(text)
    if not m:
        raise ValueError(f"no fuzz target in {bin_dir/'arvo'}")
    asan = _ASAN_RE.search(text)
    return m.group(1), (asan.group(1) if asan else "detect_leaks=0")


def build_fuzz_cmd(bin_dir: Path, corpus_dir: Path, seeds_dir: Path,
                   artifacts_dir: Path, seconds: int,
                   runner: str = DEFAULT_RUNNER) -> list:
    """corpus_dir is mounted rw and passed first: libFuzzer writes every new
    interesting input there, so the corpus compounds across rounds.
    The command is wrapped in `timeout -s SIGKILL` INSIDE the container so a
    hung target still exits -> `--rm` can clean the container up (leaked
    containers were observed when only the python-side wait timed out)."""
    import shlex

    target, asan = parse_arvo_script(bin_dir)
    inner = (f"env LD_LIBRARY_PATH=/out-libs ASAN_OPTIONS={asan} "
             f"/out/{target} -max_total_time={seconds} "
             f"-artifact_prefix=/artifacts/ -rss_limit_mb=2560 -timeout=25 "
             f"/corpus /seeds")
    return [
        "docker", "run", "--rm",
        "-v", f"{bin_dir / 'out'}:/out:ro",
        "-v", f"{bin_dir / 'libs'}:/out-libs:ro",
        "-v", f"{seeds_dir}:/seeds:ro",
        "-v", f"{artifacts_dir}:/artifacts",
        "-v", f"{corpus_dir}:/corpus",
        runner,
        "bash", "-c", f"timeout -s SIGKILL {seconds + 60} {inner}",
    ]


_STATS_RE = re.compile(r"cov:\s*(\d+)\s+ft:\s*(\d+)\s+corp:\s*(\d+)/(\d+)\w*")
_DICT_BLOCK_RE = re.compile(r"###### Recommended dictionary\. ######\n(.*?)###### End", re.S)
_DICT_ITEM_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_fuzz_stats(tail: str) -> str:
    """Digest a libFuzzer log tail into a compact hint block for the model."""
    cov = _STATS_RE.findall(tail)
    lines = []
    if cov:
        c = cov[-1]
        lines.append(f"fuzzer coverage so far: cov={c[0]} features={c[1]} "
                     f"corpus_units={c[2]} (total {c[3]}b)")
    dicts = _DICT_BLOCK_RE.findall(tail)
    if dicts:
        items = _DICT_ITEM_RE.findall(dicts[-1])[:12]
        if items:
            shown = ", ".join(items)
            lines.append(f"fuzzer dictionary hints (byte sequences the parser "
                         f"recognizes): {shown}")
    return "\n".join(lines)


def build_repro_cmd(bin_dir: Path, poc_path: Path,
                    runner: str = DEFAULT_RUNNER) -> list:
    """Single-input replay, same mount scheme as the submission server.
    Also wrapped in an in-container SIGKILL timeout (hung target -> clean exit)."""
    import shlex

    target, asan = parse_arvo_script(bin_dir)
    inner = (f"env LD_LIBRARY_PATH=/out-libs ASAN_OPTIONS={asan} "
             f"/out/{target} /tmp/poc")
    return [
        "docker", "run", "--rm",
        "-v", f"{bin_dir / 'out'}:/out:ro",
        "-v", f"{bin_dir / 'libs'}:/out-libs:ro",
        "-v", f"{Path(poc_path).absolute()}:/tmp/poc:ro",
        runner,
        "bash", "-c", f"timeout -s SIGKILL 30 {shlex.quote(inner)}",
    ]


def repro_single(task_id: str, poc_path: str,
                 data_dir: Path = DEFAULT_DATA_DIR,
                 runner: str = DEFAULT_RUNNER,
                 timeout: int = 40):
    """Replay one input on the vul build; returns RunOutcome for triage."""
    from plugins.env_manager import RunOutcome

    subid = task_id.split(":", 1)[1]
    bin_dir = data_dir / "arvo" / subid / "vul"
    cmd = build_repro_cmd(bin_dir, Path(poc_path), runner)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return RunOutcome(ok=True, returncode=r.returncode,
                          stdout=(r.stdout or "")[-20000:])
    except subprocess.TimeoutExpired:
        from plugins.env_manager import RunOutcome as RO
        return RO(ok=False, timed_out=True)


def find_crash(artifacts_dir: Path) -> Optional[Path]:
    """crash-* artifacts are genuine crashes; timeout-/oom-* are not."""
    crashes = sorted(artifacts_dir.glob("crash-*"))
    return crashes[-1] if crashes else None


def fuzz_one(task_id: str, seed_paths: list, work_dir: str | Path,
             seconds: int = 30,
             data_dir: Path = DEFAULT_DATA_DIR,
             runner: str = DEFAULT_RUNNER) -> tuple:
    """Run libFuzzer on the vul build. Corpus persists in work_dir/corpus
    across calls (compounds); seeds/artifacts are rebuilt each call.
    Returns (crash_path_or_None, output_tail)."""
    subid = task_id.split(":", 1)[1]
    bin_dir = data_dir / "arvo" / subid / "vul"
    work_dir = Path(work_dir)
    seeds = work_dir / "seeds"
    artifacts = work_dir / "artifacts"
    corpus = work_dir / "corpus"
    for d in (seeds, artifacts):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
    corpus.mkdir(parents=True, exist_ok=True)   # persist, never wiped
    copied = 0
    for p in seed_paths:
        p = Path(p)
        if p.exists():
            shutil.copyfile(p, seeds / f"seed-{copied}")
            copied += 1

    cmd = build_fuzz_cmd(bin_dir, corpus, seeds, artifacts, seconds, runner)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=seconds + 120)
        tail = ((r.stdout or "") + (r.stderr or ""))[-4000:]
    except subprocess.TimeoutExpired:
        tail = "fuzz container timed out"
    return find_crash(artifacts), tail
