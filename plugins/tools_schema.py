"""Tool schema exposed to the model (MCP-style definitions).

Kept as data so it can be registered into dsh's MCP layer (or any MCP server)
without touching the core. Allow-lists are per task_type, following the
reference mcp-server.yaml `session_tools` pattern.
"""
from agent.contract import TaskType

TOOLS = [
    {
        "name": "get_task_brief",
        "description": "Read the vulnerability description and repo manifest for the current task.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "read_file_slice",
        "description": "Read a bounded slice of one repo file. start/line window <= 400 lines per call.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_code",
        "description": "Regex search across the repo manifest (grep). Returns file:line matches.",
        "input_schema": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}, "glob": {"type": "string"}},
            "required": ["pattern"],
        },
    },
    {
        "name": "kb_query",
        "description": "Query the lightweight security knowledge base (vehicle protocol vulns, memory-safety classes, task metadata).",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 5},
                "source": {"type": "string", "enum": ["vehicle", "memory", "task-meta", None]},
            },
            "required": ["query"],
        },
    },
    {
        "name": "write_poc",
        "description": "Persist a PoC candidate file. Returns the path that diff-verifier will consume.",
        "input_schema": {
            "type": "object",
            "properties": {"filename": {"type": "string"}, "content_b64": {"type": "string"}},
            "required": ["filename", "content_b64"],
        },
    },
    {
        "name": "create_exec_task",
        "description": "Async: submit a sandbox run (build or execute PoC). Returns task_id immediately.",
        "input_schema": {
            "type": "object",
            "properties": {"image": {"type": "string", "enum": ["vul", "fix"]}, "poc_path": {"type": "string"}},
            "required": ["image", "poc_path"],
        },
    },
    {
        "name": "get_exec_status",
        "description": "Async trio: poll a submitted exec task.",
        "input_schema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]},
    },
    {
        "name": "get_exec_result",
        "description": "Async trio: fetch completed run outcome (truncated stdout/stderr, crash signature).",
        "input_schema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]},
    },
]

# per-task-type allow-list (None = allow all, [] = deny all)
SESSION_TOOLS = {
    TaskType.LOCATE: ["get_task_brief", "search_code", "read_file_slice", "kb_query"],
    TaskType.HYPOTHESIZE: ["get_task_brief", "search_code", "read_file_slice"],
    TaskType.CONSTRUCT: ["get_task_brief", "search_code", "read_file_slice",
                         "write_poc", "create_exec_task", "get_exec_status", "get_exec_result"],
    TaskType.VERIFY: ["create_exec_task", "get_exec_status", "get_exec_result"],
}


def allowed_tools(task_type: TaskType) -> list:
    return SESSION_TOOLS.get(task_type, [])
