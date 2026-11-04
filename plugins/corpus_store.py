"""Corpus-template construction (ladder 3).

Every fuzz round leaves corpus inputs in each batch's tasks/<id>/fuzz-out/corpus/.
Those inputs already pass format checks and reach deep parser states -- they are
'valid containers' by construction. Instead of asking the model to synthesize a
file from scratch (the 84% no_trigger failure mode), we hand it 1-2 corpus
templates and ask for a targeted mutation toward the hypothesis.

Central store: /data/cybergym/corpus/<task>/  (aggregated from all batches).
"""
import shutil
from pathlib import Path
from typing import Optional

BATCHES_ROOT = Path("/data/cybergym/agent-tasks")
CENTRAL = Path("/data/cybergym/corpus")
MAX_PER_TASK = 64          # cap central store per task
TEMPLATE_MAX_BYTES = 512   # what we show the model


def collect(task_id: str, batches_root: Path = BATCHES_ROOT,
            central: Path = CENTRAL) -> int:
    """Aggregate corpus files for one task from every batch dir into central."""
    safe = task_id.replace(":", "_")
    dest = central / safe
    dest.mkdir(parents=True, exist_ok=True)
    have = {p.name: p for p in dest.iterdir()} if dest.exists() else {}
    n = 0
    for corpus in sorted(batches_root.glob(f"*/tasks/{safe}/fuzz-out/corpus/*")):
        if not corpus.is_file() or corpus.stat().st_size == 0:
            continue
        key = f"{corpus.stat().st_size}-{corpus.name}"
        if key in have or len(have) >= MAX_PER_TASK:
            continue
        target = dest / key
        shutil.copyfile(corpus, target)
        have[key] = target
        n += 1
    return n


def templates_for(task_id: str, k: int = 2, max_bytes: int = TEMPLATE_MAX_BYTES,
                  central: Path = CENTRAL) -> list:
    """Pick k diverse corpus templates: prefer the LARGEST distinct sizes
    (large inputs survive format checks furthest), return (hex, note) pairs."""
    safe = task_id.replace(":", "_")
    d = central / safe
    if not d.exists():
        return []
    files = [p for p in d.iterdir() if p.is_file() and p.stat().st_size > 0]
    files.sort(key=lambda p: p.stat().st_size, reverse=True)
    picked, seen_sizes = [], set()
    for p in files:
        sz = p.stat().st_size
        if sz in seen_sizes:
            continue
        seen_sizes.add(sz)
        data = p.read_bytes()[:max_bytes]
        picked.append({
            "hex": data.hex(),
            "size": sz,
            "truncated": sz > max_bytes,
        })
        if len(picked) >= k:
            break
    return picked
