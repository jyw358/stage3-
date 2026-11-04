"""S2: Tool Manifest 加载器——声明式工具注册,五类接入统一管理。

用法:
  from plugins.tool_manifest import ManifestRegistry
  reg = ManifestRegistry()
  reg.load_dir("tools/")               # 加载 YAML/JSON Manifest 文件
  reg.register({"name": "nmap", ...})  # 直接注册字典
  tool = reg.get("nmap")
  result = reg.invoke("nmap", {"target": "192.168.1.1", "ports": "1-1000"})

与 tools_schema.py 的关系:TOOLS 列表是 LLM 侧白名单(静态);
ManifestRegistry 是运行侧注册(动态加载,含调用代理)。
"""
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

import yaml

ACCESS_TYPES = {"cli", "mcp", "http", "sdk", "gui"}
SAFETY_LEVELS = {"safe", "caution", "dangerous"}


class ManifestError(Exception):
    pass


class ToolManifest:
    """一个工具的声明式描述。"""

    def __init__(self, data: dict):
        self._validate(data)
        self.__dict__.update(data)

    def _validate(self, d: dict) -> None:
        for key in ("name", "version", "access_type", "description",
                    "input_schema", "output_schema"):
            if key not in d:
                raise ManifestError(f"missing required field: {key}")
        if d["access_type"] not in ACCESS_TYPES:
            raise ManifestError(f"invalid access_type: {d['access_type']}")
        if d.get("safety_level") and d["safety_level"] not in SAFETY_LEVELS:
            raise ManifestError(f"invalid safety_level: {d['safety_level']}")

    @property
    def is_dangerous(self) -> bool:
        return getattr(self, 'safety_level', 'safe') == 'dangerous'

    def to_llm_schema(self) -> dict:
        """转为 tools_schema.py TOOLS 列表格式(LLM 白名单用)。"""
        return {"name": self.name, "description": self.description,
                "input_schema": self.input_schema}


class ManifestRegistry:
    """Manifest 注册表 + 统一调用代理。"""

    def __init__(self, root: Optional[Path] = None):
        self.tools: dict[str, ToolManifest] = {}
        self.root = root

    def register(self, data: dict) -> ToolManifest:
        m = ToolManifest(data)
        self.tools[m.name] = m
        return m

    def load_dir(self, dir_path) -> int:
        """加载目录下所有 .yaml/.yml/.json Manifest 文件。"""
        n = 0
        for f in sorted(Path(dir_path).glob('*')):
            if f.suffix in ('.yaml', '.yml'):
                data = yaml.safe_load(f.read_text(encoding='utf-8'))
            elif f.suffix == '.json':
                data = json.loads(f.read_text(encoding='utf-8'))
            else:
                continue
            if isinstance(data, dict):
                self.register(data)
                n += 1
        return n

    def get(self, name: str) -> ToolManifest:
        if name not in self.tools:
            raise ManifestError(f"tool not registered: {name}")
        return self.tools[name]

    def invoke(self, name: str, params: dict, timeout_s: int = 300) -> dict:
        """统一调用代理:按 access_type 分发。"""
        m = self.get(name)
        t0 = time.time()
        try:
            if m.access_type == "cli":
                result = self._invoke_cli(m, params, timeout_s)
            elif m.access_type == "http":
                result = self._invoke_http(m, params, timeout_s)
            elif m.access_type == "mcp":
                result = self._invoke_mcp(m, params)
            elif m.access_type == "sdk":
                result = self._invoke_sdk(m, params)
            elif m.access_type == "gui":
                result = {"status": "error",
                          "evidence": "gui bridge not yet implemented (S2 后期)",
                          "semantic": {}}
            else:
                result = {"status": "error", "evidence": f"unknown type {m.access_type}",
                          "semantic": {}}
        except subprocess.TimeoutExpired:
            result = {"status": "timeout", "evidence": "", "semantic": {}}
        except Exception as e:
            result = {"status": "error", "evidence": str(e)[:500], "semantic": {}}
        result["_tool"] = name
        result["_wall_s"] = round(time.time() - t0, 1)
        return result

    def _invoke_cli(self, m: ToolManifest, params: dict, timeout: int) -> dict:
        cmd = m.invoke.get("command", "")
        for k, v in params.items():
            cmd = cmd.replace("{" + k + "}", str(v))
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                           timeout=timeout)
        return {"status": "success" if r.returncode == 0 else "error",
                "evidence": (r.stdout or r.stderr)[-4000:],
                "semantic": self._parse_semantic(m, r.stdout or "")}

    def _invoke_http(self, m: ToolManifest, params: dict, timeout: int) -> dict:
        import urllib.request
        import urllib.parse
        url = m.invoke.get("endpoint", "")
        if m.invoke.get("method", "GET").upper() == "GET":
            if params:
                url += "?" + urllib.parse.urlencode(params)
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(url, data=json.dumps(params).encode(),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors='replace')
        return {"status": "success", "evidence": body[:4000],
                "semantic": self._parse_semantic(m, body)}

    def _invoke_mcp(self, m: ToolManifest, params: dict) -> dict:
        return {"status": "error", "evidence": "MCP invoke via pi harness(T1.1 路径)",
                "semantic": {}}

    def _invoke_sdk(self, m: ToolManifest, params: dict) -> dict:
        return {"status": "error",
                "evidence": f"sdk adapter pending: {m.invoke.get('module', '?')}",
                "semantic": {}}

    def _parse_semantic(self, m: ToolManifest, raw_output: str) -> dict:
        """尝试解析为结构化语义(工具特定的 output_schema.semantic)。"""
        try:
            parsed = json.loads(raw_output)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass
        return {"raw_length": len(raw_output)}
