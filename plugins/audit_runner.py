"""S7: M2 代码审计模块——审计运行器(桥接甲方 SAST 引擎或外部工具)。

定位:平台集成口径,不自研静态引擎(计划 v3.3.1 §9 S7)。
将甲方现有 SAST(≥10 语言/2000 规则/污点+SMT)的扫描结果
归一为统一 Schema(Evidence/AgentStep/ToolCall),进入审计库。

用法:
  from plugins.audit_runner import AuditRunner, AuditTarget
  runner = AuditRunner(sut="semgrep")  # or "checkmarx" / "codeql"
  result = runner.scan(AuditTarget(path="src/", language="c"))
"""
import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AuditTarget:
    """审计目标:一段代码/一个目录。"""
    path: str                        # 文件或目录
    language: str = "auto"           # c/cpp/java/python/go/js/...
    ruleset: Optional[str] = None    # 规则集名称(None=默认)
    incremental: bool = False        # 增量扫描(仅变更文件)


@dataclass
class AuditFinding:
    """结构化审计发现(M2 评审 15① 的四要素口径)。"""
    file: str
    line: int
    cwe: str
    severity: str          # critical/high/medium/low/info
    description: str
    code_snippet: str = ""  # 相关代码片段
    poc_hint: str = ""      # 触发 PoC 线索(验证状态:未验证)
    fix_suggestion: str = ""  # 修复建议
    source: str = ""        # 来源工具(semgrep/codeql/...)

    def to_dict(self) -> dict:
        return vars(self)


class AuditRunner:
    """桥接外部 SAST 工具,归一输出。"""

    PROVIDERS = {
        "semgrep": {
            "cmd": "semgrep --json --config {ruleset} {path}",
            "parse": "_parse_semgrep",
        },
        "grep": {  # 内置 mock(grep 检测器,用于管线校准)
            "cmd": "grep -rnE \"{pattern}\" {path} --include='*.c' --include='*.cpp' --include='*.java' --include='*.py' --include='*.go' --include='*.js' --include='*.h' 2>/dev/null || true",
            "parse": "_parse_grep",
            "default_pattern": "memcpy\\(|strcpy\\(|sprintf\\(|system\\(|exec\\(",
        },
    }

    def __init__(self, sut: str = "grep", timeout_s: int = 900):
        if sut not in self.PROVIDERS:
            raise ValueError(f"unknown SUT: {sut}, available: {list(self.PROVIDERS)}")
        self.sut = sut
        self.timeout_s = timeout_s
        self.findings: list[AuditFinding] = []

    def scan(self, target: AuditTarget) -> dict:
        """执行扫描并归一为统一格式。"""
        prov = self.PROVIDERS[self.sut]
        ruleset = target.ruleset or "auto"
        pattern = prov.get("default_pattern", "")

        cmd = prov["cmd"].format(
            path=target.path,
            ruleset=ruleset,
            pattern=pattern,
        )
        t0 = time.time()
        try:
            r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                               timeout=self.timeout_s)
            raw = r.stdout or ""
            rc = r.returncode
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "findings": [], "wall_s": time.time() - t0}
        except Exception as e:
            return {"status": "error", "error": str(e), "findings": [], "wall_s": 0}

        parser = getattr(self, prov["parse"])
        self.findings = parser(raw, target)
        return {
            "status": "success" if rc in (0, 1) else "error",
            "sut": self.sut,
            "findings": [f.to_dict() for f in self.findings],
            "n_findings": len(self.findings),
            "wall_s": round(time.time() - t0, 1),
            "target": vars(target),
        }

    def _parse_semgrep(self, raw: str, target: AuditTarget) -> list[AuditFinding]:
        """解析 semgrep JSON 输出。"""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        out = []
        for r in data.get("results", []):
            out.append(AuditFinding(
                file=r.get("path", ""),
                line=r.get("start", {}).get("line", 0),
                cwe=r.get("extra", {}).get("metadata", {}).get("cwe", ""),
                severity=r.get("extra", {}).get("severity", "info"),
                description=r.get("check_id", ""),
                code_snippet=r.get("extra", {}).get("lines", "")[:200],
                source="semgrep",
            ))
        return out

    def _parse_grep(self, raw: str, target: AuditTarget) -> list[AuditFinding]:
        """解析 grep 输出(内置 mock 检测器)。"""
        out = []
        for line in raw.splitlines():
            parts = line.split(":", 2)
            if len(parts) >= 2:
                out.append(AuditFinding(
                    file=parts[0],
                    line=int(parts[1]) if parts[1].isdigit() else 0,
                    cwe=" CWE-120",  # mock:关键词匹配默认归为缓冲区溢出
                    severity="medium",
                    description=f"keyword match: {parts[2][:80]}" if len(parts) > 2 else "",
                    source="grep-mock",
                ))
        return out

    def to_report(self) -> dict:
        """生成四要素报告(M2 评审 15①)。"""
        return {
            "vulnerability_info": [
                {"file": f.file, "line": f.line, "cwe": f.cwe, "severity": f.severity,
                 "description": f.description}
                for f in self.findings
            ],
            "code_snippets": [f.code_snippet[:200] for f in self.findings if f.code_snippet],
            "poc_status": ["未验证"] * len(self.findings),
            "fix_suggestions": [f.fix_suggestion or "参考 CWE 修复指南" for f in self.findings],
        }
