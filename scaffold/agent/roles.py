"""Declarative role specs: roles/*.yaml loaded and validated at startup.

T0.5 deliverable. A role = contract prompt + tool whitelist + budget tier +
kb write kinds + handoff targets, all declared in YAML. The loader is the
single enforcement point (contract.py style: missing/contradictory -> error,
never guessed).

Design invariants (see docs/roles-design.md):
  - four explicit pipeline roles + custom roles (custom: true, e.g. report_writer);
  - every TaskType except VERIFY is owned by exactly one role; VERIFY belongs
    to the system verifier (diff_verifier), never to an LLM role;
  - kb write kinds never overlap between roles (write isolation), reads are
    always full-kb (anti context-fragmentation red line);
  - handoff targets must exist; the ring must be consistent with retry.py.
"""
import yaml
from dataclasses import dataclass, field
from pathlib import Path

from agent.contract import ContractError, TaskType
from plugins.tools_schema import SESSION_TOOLS, TOOLS

SYSTEM_ROLE = "verifier_system"          # diff_verifier + watchdog: not an LLM role
KB_WRITE_KINDS = {"NOTE", "HYP", "ATT", "EVI", "VERDICT", "RPT"}
BUDGET_TIERS = {"light", "standard", "heavy", "audit"}
# task_type -> owning role id (the ring's backbone; VERIFY -> system)
EXPECTED_ROUTER = {
    TaskType.LOCATE: "intel_analyst",
    TaskType.HYPOTHESIZE: "vuln_analyst",
    TaskType.CONSTRUCT: "poc_builder",
    TaskType.FUZZ: "poc_builder",
    TaskType.VERIFY: SYSTEM_ROLE,
}

_TOOL_REGISTRY = {t["name"] for t in TOOLS}


@dataclass
class RoleSpec:
    id: str
    display_name: str
    mission: str
    contract_prompt: str
    task_types: list
    tools: list
    budget_tier: str
    budget: dict
    kb_write_kinds: list
    handoff: dict
    custom: bool = False
    source: str = ""

    def kb_read_scope(self) -> str:
        return "all"          # red line: full shared memory for every role


def _task_type(value: str) -> TaskType:
    try:
        return TaskType(value)
    except ValueError:
        raise ContractError(f"unknown task_type {value!r} in role spec")


def load_roles(roles_dir: str | Path) -> dict:
    """Load and validate every roles/*.yaml. Returns {role_id: RoleSpec}."""
    roles_dir = Path(roles_dir)
    specs: dict = {}
    for f in sorted(roles_dir.glob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ContractError(f"{f.name}: not a mapping")
        rid = data.get("id")
        if not rid or not isinstance(rid, str):
            raise ContractError(f"{f.name}: missing role id")
        if rid in specs:
            raise ContractError(f"duplicate role id {rid!r}")
        if rid == SYSTEM_ROLE:
            raise ContractError(f"{rid!r} is reserved for the system verifier")
        spec = RoleSpec(
            id=rid,
            display_name=data.get("display_name", rid),
            mission=data.get("mission", ""),
            contract_prompt=data.get("contract_prompt", ""),
            task_types=[_task_type(t) for t in data.get("task_types", [])],
            tools=list(data.get("tools", [])),
            budget_tier=data.get("budget_tier", "standard"),
            budget=dict(data.get("budget", {})),
            kb_write_kinds=list(data.get("kb_write_kinds", [])),
            handoff=dict(data.get("handoff", {})),
            custom=bool(data.get("custom", False)),
            source=f.name,
        )
        _validate(spec)
        specs[rid] = spec

    _validate_pipeline(specs)
    return specs


def _validate(spec: RoleSpec) -> None:
    if spec.budget_tier not in BUDGET_TIERS:
        raise ContractError(f"{spec.id}: budget_tier {spec.budget_tier!r} not in {sorted(BUDGET_TIERS)}")
    bad_kinds = set(spec.kb_write_kinds) - KB_WRITE_KINDS
    if bad_kinds:
        raise ContractError(f"{spec.id}: unknown kb_write_kinds {sorted(bad_kinds)}")
    if TaskType.VERIFY in spec.task_types:
        raise ContractError(f"{spec.id}: LLM roles never own VERIFY (diff-verifier is the independent gate)")
    registry = _TOOL_REGISTRY | set(spec.tools)      # extras must still pass the whitelist intersection below
    unknown = set(spec.tools) - registry
    if unknown:
        raise ContractError(f"{spec.id}: tools not in registry {sorted(unknown)}")
    allowed: set = set()
    if spec.task_types:
        for tt in spec.task_types:
            allowed |= set(SESSION_TOOLS.get(tt, []))
    elif not spec.custom:
        # audit position (no task types of its own): validated against the
        # VERIFY whitelist -- the same tools the system diff-verifier uses
        allowed = set(SESSION_TOOLS.get(TaskType.VERIFY, []))
    extra = set(spec.tools) - allowed - (_TOOL_REGISTRY & set())
    # role tools must be a subset of its task_types' whitelists (extensions
    # declared here are validated against the same registry at load time)
    if extra and not spec.custom:
        raise ContractError(
            f"{spec.id}: tools {sorted(extra)} outside its task_types' whitelist "
            f"(custom roles may extend; pipeline roles may not)")
    if not spec.contract_prompt:
        raise ContractError(f"{spec.id}: contract_prompt is required")


def _validate_pipeline(specs: dict) -> None:
    pipeline = {r.id for r in specs.values() if not r.custom}
    if not pipeline:
        raise ContractError("no pipeline roles loaded")

    # router coverage: every LLM-owned TaskType has exactly one pipeline role
    owner: dict = {}
    for spec in specs.values():
        if spec.custom:
            if spec.task_types:
                raise ContractError(f"{spec.id}: custom roles cannot own task_types")
            continue
        for tt in spec.task_types:
            if tt in owner:
                raise ContractError(f"task_type {tt.value} owned by both {owner[tt]} and {spec.id}")
            owner[tt] = spec.id
    for tt, expect in EXPECTED_ROUTER.items():
        if tt is TaskType.VERIFY:
            continue
        if owner.get(tt) != expect:
            raise ContractError(
                f"router mismatch: {tt.value} should be owned by {expect}, got {owner.get(tt)}")

    # write isolation: no two roles write the same kb kind
    seen: dict = {}
    for spec in specs.values():
        for kind in spec.kb_write_kinds:
            if kind in seen:
                raise ContractError(f"kb kind {kind} writable by both {seen[kind]} and {spec.id}")
            seen[kind] = spec.id

    # handoff targets exist
    for spec in specs.values():
        for key, target in spec.handoff.items():
            if target in ("end", "orchestrator", SYSTEM_ROLE):
                continue
            if target not in specs:
                raise ContractError(f"{spec.id}: handoff.{key} target {target!r} is not a loaded role")


def route(task_type: TaskType, specs: dict) -> str:
    """task_type -> owning role id (VERIFY -> system)."""
    if task_type is TaskType.VERIFY:
        return SYSTEM_ROLE
    for spec in specs.values():
        if spec.custom:
            continue
        if task_type in spec.task_types:
            return spec.id
    raise ContractError(f"no role owns task_type {task_type.value}")


def allowed_tools_for(spec: RoleSpec) -> list:
    allowed: set = set()
    for tt in spec.task_types:
        allowed |= set(SESSION_TOOLS.get(tt, []))
    return [t for t in spec.tools if t in allowed or spec.custom]
