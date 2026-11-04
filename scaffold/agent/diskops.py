"""Disk-space preflight for any large data operation (question banks, ARVO
subsets, docker images). Every bulk download/build step must call require_free()
BEFORE it starts writing -- running out of disk mid-download corrupts state
and wastes hours.

Policy: fail fast, report the drive, the requirement and the shortfall.
"""
import shutil
from pathlib import Path


class InsufficientDisk(Exception):
    pass


def free_bytes(path) -> int:
    p = Path(path)
    probe = p if p.exists() else _nearest_existing(p)
    return shutil.disk_usage(str(probe)).free


def _nearest_existing(p: Path) -> Path:
    cur = p if p.is_absolute() else p.resolve()
    while not cur.exists():
        if cur.parent == cur:
            raise FileNotFoundError(f"no existing ancestor for {p}")
        cur = cur.parent
    return cur


def require_free(path, min_bytes: int, label: str = "operation") -> int:
    """Raise InsufficientDisk if the drive holding `path` has less than
    min_bytes free. Returns the actual free bytes."""
    free = free_bytes(path)
    if free < min_bytes:
        drive = _nearest_existing(Path(path)).anchor or str(path)
        raise InsufficientDisk(
            f"{label} needs {min_bytes / 2**30:.1f} GiB free on {drive}, "
            f"only {free / 2**30:.1f} GiB available "
            f"(short by {(min_bytes - free) / 2**30:.1f} GiB)")
    return free


def gb(n: float) -> int:
    return int(n * 2**30)
