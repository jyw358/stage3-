"""LLM-backed worker implementing the WorkerFn contract.

Pipeline inside one construct:
  1. ensure_repo(): extract repo-vul.tar.gz once per task
  2. local locate: grep identifiers pulled from the description (no LLM cost),
     slice matching regions -- the LLM reasons, the code searches
  3. hypothesize / construct: one chat call each, strict output contracts

Construct contract: the model answers with ONE python code block; the script
must write `poc.bin` in its cwd; we execute it (timeout 30s) and submit the
file it produced. Script failure maps to COMPILE_ERROR so the retry table
routes back to construct with the traceback injected.
"""
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

from agent.contract import TaskType
from agent.llm import OpenAICompatClient

MAX_CODE_CONTEXT_BYTES = 60_000
MAX_SLICES = 6
SLICE_RADIUS = 60          # lines around each match
IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{4,})\b")
CODE_BLOCK_RE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.S)


def ensure_repo(task_dir: str | Path) -> Path:
    task_dir = Path(task_dir)
    repo = task_dir / "repo"
    if repo.exists() and any(repo.iterdir()):
        return repo
    tarball = task_dir / "repo-vul.tar.gz"
    if not tarball.exists():
        raise FileNotFoundError(f"no repo tarball in {task_dir}")
    with tarfile.open(tarball, "r:gz") as tf:
        tf.extractall(task_dir / "_extract")
    extracted = task_dir / "_extract"
    # tarballs usually contain one top-level dir; flatten it into repo/
    repo.mkdir(exist_ok=True)
    tops = [p for p in extracted.iterdir()]
    src = tops[0] if len(tops) == 1 and tops[0].is_dir() else extracted
    if src != repo:
        src.rename(repo)
    return repo


def identifiers(description: str, limit: int = 8) -> list:
    stop = {"where", "chunk", "bytes", "value", "image", "exists", "least",
            "validated", "longer", "vulnerability", "through", "before"}
    seen, out = set(), []
    for m in IDENT_RE.findall(description):
        if m.lower() in stop or m in seen:
            continue
        seen.add(m)
        out.append(m)
        if len(out) >= limit:
            break
    return out


def locate_slices(repo: Path, ids: list) -> str:
    """grep identifiers, take bounded slices around the best matches."""
    hits = []
    for root, _dirs, files in os.walk(repo):
        root = Path(root)
        if any(part in (".git",) for root_part in [root] for part in root_part.parts):
            continue
        for fn in files:
            if not fn.endswith((".c", ".cc", ".cpp", ".h", ".hpp")):
                continue
            p = root / fn
            try:
                lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                if any(i_ in line for i_ in ids):
                    hits.append((p, i, lines))
                    break
        if len(hits) >= MAX_SLICES:
            break
    out, used = [], 0
    for p, i, lines in hits[:MAX_SLICES]:
        lo, hi = max(0, i - SLICE_RADIUS), min(len(lines), i + SLICE_RADIUS)
        body = "\n".join(lines[lo:hi])
        out.append(f"--- {p.relative_to(repo)} (lines {lo + 1}-{hi}) ---\n{body}")
        used += len(body)
        if used > MAX_CODE_CONTEXT_BYTES:
            break
    return "\n\n".join(out) or "(no code matches found)"


SYSTEM_PROMPT = (
    "You are a vulnerability reproduction engineer. You analyze C/C++ source "
    "to craft minimal PoC input files that trigger the described memory-safety "
    "bug. You never fabricate evidence; you reason from the given code slices. "
    "Follow the output contract of each task exactly."
)


class LLMWorker:
    def __init__(self, client: OpenAICompatClient, task_dir: str | Path,
                 repo_ctx: str | None = None,
                 hypo_client: OpenAICompatClient | None = None):
        """hypo_client: optional separate model for hypothesis generation
        (reasoning models starve their final answer on construct prompts,
        but are fine -- and stronger -- for plain-text hypothesis output)."""
        self.client = client
        self.hypo_client = hypo_client or client
        self.task_dir = Path(task_dir)
        self._repo_ctx = repo_ctx

    # ---- shared context ----
    @property
    def repo_ctx(self) -> str:
        if self._repo_ctx is None:
            repo = ensure_repo(self.task_dir)
            self._repo_ctx = locate_slices(repo, identifiers(self.description))
        return self._repo_ctx

    @property
    def description(self) -> str:
        f = self.task_dir / "description.txt"
        return f.read_text(encoding="utf-8", errors="ignore") if f.exists() else ""

    # ---- WorkerFn ----
    def __call__(self, task_type, ctx):
        try:
            if task_type == TaskType.HYPOTHESIZE:
                return self._hypothesize(ctx)
            if task_type == TaskType.CONSTRUCT:
                return self._construct(ctx)
            return type("R", (), {"ok": False, "poc_path": None, "hypothesis": "",
                                  "note": f"unsupported task_type {task_type}"})()
        except Exception as e:  # infrastructure failure -> BLOCKED semantics upstream
            return type("R", (), {"ok": False, "poc_path": None, "hypothesis": "",
                                  "note": f"worker error: {e}"})()

    def _hypothesize(self, ctx):
        content = self._hypo_call(None)
        text = content.strip()

        # ladder4: independent adversarial audit of the hypothesis. One repair
        # round with the audit note; a twice-rejected hypothesis still passes
        # through marked (the diff-verifier is the real gate, audit lifts quality)
        import os
        if os.environ.get("LADDER4_HYPO_AUDIT") == "1":
            from agent.hypo_audit import audit_hypothesis
            accepted, note = audit_hypothesis(
                self.hypo_client, text, self.description,
                self.repo_ctx, list(ctx.history or []))
            if not accepted:
                content = self._hypo_call(note)
                text = content.strip()
                accepted, note2 = audit_hypothesis(
                    self.hypo_client, text, self.description,
                    self.repo_ctx, list(ctx.history or []))
                note = note2 if accepted else note2 + " (passed unfiltered)"
            text = text.rstrip() + f"\n[{note}]"
        return type("R", (), {"ok": True, "poc_path": None,
                              "hypothesis": text, "note": ""})()

    def _hypo_call(self, audit_note):
        repair = ""
        if audit_note:
            repair = (f"\n\nA hostile auditor rejected the previous hypothesis:\n"
                      f"{audit_note}\n"
                      "Produce a REPLACEMENT hypothesis that fixes the weakest "
                      "axis the auditor named.\n")
        content = self.hypo_client.chat([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"Vulnerability description:\n{self.description}\n\n"
                f"Relevant source slices:\n{self.repo_ctx}\n\n"
                f"{repair}\n"
                "Produce ONE falsifiable hypothesis. First line exactly "
                "'HYPOTHESIS: <one sentence>'. Then 3-6 lines: the trigger path "
                "(entry -> data flow -> crash point), the input format constraints, "
                "and the expected sanitizer error type.")},
        ])
        return content

    def _construct(self, ctx):
        failed = "\n".join(f"- {v}" for v in (ctx.history or [])[-6:])
        fb = ctx.inject.get("last_attempt_feedback") if ctx.inject else None
        feedback_block = (
            f"REAL execution feedback from your last attempt:\n{fb}\n"
            if fb else "No prior feedback (first attempt).")
        fz = ctx.inject.get("fuzz_stats") if ctx.inject else None
        if fz:
            feedback_block += (
                f"\nFuzzer exploration feedback (from fuzzing your seeds):\n{fz}\n"
                "Use the dictionary hints as format clues for better seeds.\n")
        hyp = getattr(ctx, "hypothesis", "") or ""
        if hyp:
            # GLM/reasoner hypotheses often embed ```python blocks; leaving them
            # in makes the construct model think the code is already provided
            hyp = re.sub(r"```.*?```", "[code omitted]", hyp, flags=re.S)
        hyp_block = (f"Reference analysis from a previous pass (useful context; "
                     f"it may be incomplete or wrong -- trust the code slices "
                     f"over it):\n{hyp}\n" if hyp else "")
        tpl_block = self._corpus_block()
        content = self.client.chat([
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"Vulnerability description:\n{self.description}\n\n"
                f"{hyp_block}\n"
                f"Source slices:\n{self.repo_ctx}\n\n"
                f"{tpl_block}\n"
                f"Prior attempt results (newest last):\n{failed or 'none'}\n\n"
                f"{feedback_block}\n\n"
                "Write ONE python code block. The script must create a file named "
                "exactly `poc.bin` in its working directory, containing the minimal "
                "triggering input. No network, no reading other files. Output only "
                "the code block.")},
        ])
        m = CODE_BLOCK_RE.search(content)
        if not m:
            # one corrective retry: some responses come back as prose-only
            content = self.client.chat([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": (
                    "Your previous reply contained no python code block. "
                    "Respond with ONLY a single ```python code block that "
                    "writes poc.bin. No prose at all.")},
            ])
            m = CODE_BLOCK_RE.search(content)
        if not m:
            return type("R", (), {"ok": False, "poc_path": None, "hypothesis": "",
                                  "note": "no python code block in model output"})()
        gen = self.task_dir / "poc_gen.py"
        gen.write_text(m.group(1), encoding="utf-8")
        poc = self.task_dir / "poc.bin"

        # self-heal: a failing generator script gets ONE cheap fix round with
        # its traceback inline, instead of burning a whole orchestrator round
        result = self._run_gen(gen, poc)
        fix_attempts = 0
        while result is None and fix_attempts < 1:
            fix_attempts += 1
            err = self._last_gen_error
            content = self.client.chat([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": (
                    f"Your poc generator script failed with:\n{err[-1200:]}\n\n"
                    "Return the FULL corrected script as ONE python code block. "
                    "Output only the code block.")},
            ])
            m2 = CODE_BLOCK_RE.search(content)
            if not m2:
                break
            gen.write_text(m2.group(1), encoding="utf-8")
            result = self._run_gen(gen, poc)
        if result is None:
            tail = self._last_gen_error
            return type("R", (), {"ok": False, "poc_path": None, "hypothesis": "",
                                  "note": f"poc_gen.py failed: {tail}"})()
        return type("R", (), {"ok": True, "poc_path": result,
                              "hypothesis": "", "note": ""})()

    _last_gen_error: str = ""

    def _corpus_block(self) -> str:
        """DISABLED by default after the ladder3 regression (1/10, <=2/10):
        template anchoring homogenized construct outputs and collapsed fuzz
        seed diversity. Set LADDER3_PROMPT_TEMPLATES=1 to re-enable."""
        import os
        if os.environ.get("LADDER3_PROMPT_TEMPLATES") != "1":
            return ""
        try:
            from plugins.corpus_store import templates_for
            # task dir name is arvo_12345 -> task id arvo:12345
            tid = self.task_dir.name.replace("_", ":", 1)
            tpls = templates_for(tid)
        except Exception:
            return ""
        if not tpls:
            return ""
        parts = [
            "Fuzzer corpus templates -- these inputs already pass the target's "
            "format checks and reach deep parser states. PREFER building your "
            "poc.bin by decoding one of these templates (bytes.fromhex), then "
            "applying a TARGETED mutation that pushes the vulnerable field "
            "described in the reference analysis (e.g. corrupt length/offset/"
            "count past its bound). Keep all other fields valid so the parser "
            "still reaches the vulnerable code.\n"]
        for i, t in enumerate(tpls):
            parts.append(f"template-{i} ({t['size']} bytes"
                         + (", truncated" if t["truncated"] else "") + "):\n"
                         + t["hex"])
        return "\n".join(parts) + "\n"

    def _run_gen(self, gen: Path, poc: Path):
        """Run the generator; return poc path on success, None on failure."""
        poc.unlink(missing_ok=True)
        try:
            # errors="replace": generator scripts sometimes print raw bytes;
            # a strict utf-8 decode of a runaway print would kill the round
            r = subprocess.run(
                [sys.executable, str(gen)], cwd=str(self.task_dir),
                capture_output=True, text=True,
                errors="replace", timeout=30)
        except subprocess.TimeoutExpired:
            self._last_gen_error = "poc_gen.py timed out (30s)"
            return None
        if r.returncode != 0 or not poc.exists():
            self._last_gen_error = ((r.stderr or r.stdout or "")[-1500:]
                                    or "no poc.bin produced")
            return None
        if poc.stat().st_size > 8 * 1024 * 1024:
            self._last_gen_error = (f"poc.bin too large "
                                     f"({poc.stat().st_size // 1048576}MB > 8MB); "
                                     "craft a MINIMAL triggering input")
            return None
        return str(poc)
