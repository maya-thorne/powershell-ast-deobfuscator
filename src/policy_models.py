"""
PowerShell ExecutionPolicy Simulation & Threat Telemetry Models.
Defines execution policy levels, scopes, bypass techniques, findings, and scope state models.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ExecutionPolicyLevel(str, Enum):
    """PowerShell execution policy permission levels."""
    RESTRICTED = "Restricted"
    ALL_SIGNED = "AllSigned"
    REMOTE_SIGNED = "RemoteSigned"
    UNRESTRICTED = "Unrestricted"
    BYPASS = "Bypass"
    UNDEFINED = "Undefined"

    @classmethod
    def from_str(cls, val: str) -> "ExecutionPolicyLevel":
        """Case-insensitive resolver with alias support."""
        if not val:
            return cls.UNDEFINED
        norm = val.strip().lower()
        aliases = {
            "restricted": cls.RESTRICTED,
            "restr": cls.RESTRICTED,
            "res": cls.RESTRICTED,
            "allsigned": cls.ALL_SIGNED,
            "all": cls.ALL_SIGNED,
            "signed": cls.ALL_SIGNED,
            "remotesigned": cls.REMOTE_SIGNED,
            "remote": cls.REMOTE_SIGNED,
            "unrestricted": cls.UNRESTRICTED,
            "unres": cls.UNRESTRICTED,
            "unr": cls.UNRESTRICTED,
            "bypass": cls.BYPASS,
            "bp": cls.BYPASS,
            "none": cls.BYPASS,
            "undefined": cls.UNDEFINED,
            "undef": cls.UNDEFINED,
            "default": cls.RESTRICTED,
        }
        return aliases.get(norm, cls.UNDEFINED)

    @property
    def rank(self) -> int:
        """Permissiveness hierarchy score: Bypass > Unrestricted > RemoteSigned > AllSigned > Restricted > Undefined."""
        ranks = {
            ExecutionPolicyLevel.BYPASS: 4,
            ExecutionPolicyLevel.UNRESTRICTED: 3,
            ExecutionPolicyLevel.REMOTE_SIGNED: 2,
            ExecutionPolicyLevel.ALL_SIGNED: 1,
            ExecutionPolicyLevel.RESTRICTED: 0,
            ExecutionPolicyLevel.UNDEFINED: -1,
        }
        return ranks.get(self, -1)

    def is_permissive(self) -> bool:
        """Returns True if the level permits executing unsigned arbitrary code."""
        return self in (ExecutionPolicyLevel.BYPASS, ExecutionPolicyLevel.UNRESTRICTED)

    def allows_script(self, is_remote: bool = False, is_signed: bool = False) -> bool:
        """Calculates if execution is permitted under this policy."""
        if self == ExecutionPolicyLevel.BYPASS:
            return True
        if self == ExecutionPolicyLevel.UNRESTRICTED:
            return True
        if self == ExecutionPolicyLevel.REMOTE_SIGNED:
            return (not is_remote) or is_signed
        if self == ExecutionPolicyLevel.ALL_SIGNED:
            return is_signed
        return False


class PolicyScope(str, Enum):
    """PowerShell execution policy configuration scopes."""
    MACHINE_POLICY = "MachinePolicy"
    USER_POLICY = "UserPolicy"
    PROCESS = "Process"
    CURRENT_USER = "CurrentUser"
    LOCAL_MACHINE = "LocalMachine"

    @classmethod
    def from_str(cls, val: str) -> Optional["PolicyScope"]:
        """Case-insensitive scope resolver."""
        if not val:
            return None
        norm = val.strip().lower()
        mapping = {
            "machinepolicy": cls.MACHINE_POLICY,
            "userpolicy": cls.USER_POLICY,
            "process": cls.PROCESS,
            "proc": cls.PROCESS,
            "currentuser": cls.CURRENT_USER,
            "user": cls.CURRENT_USER,
            "localmachine": cls.LOCAL_MACHINE,
            "machine": cls.LOCAL_MACHINE,
            "system": cls.LOCAL_MACHINE,
        }
        return mapping.get(norm, None)

    @property
    def precedence(self) -> int:
        """Precedence ranking: MachinePolicy > UserPolicy > Process > CurrentUser > LocalMachine."""
        order = {
            PolicyScope.MACHINE_POLICY: 5,
            PolicyScope.USER_POLICY: 4,
            PolicyScope.PROCESS: 3,
            PolicyScope.CURRENT_USER: 2,
            PolicyScope.LOCAL_MACHINE: 1,
        }
        return order.get(self, 0)

    @property
    def requires_elevation(self) -> bool:
        """Returns True if changing this scope requires Administrator / high-integrity elevation."""
        return self in (PolicyScope.MACHINE_POLICY, PolicyScope.LOCAL_MACHINE)


class BypassTechnique(str, Enum):
    """Categorization of PowerShell execution policy bypass techniques."""
    CLI_FLAG = "CLI_FLAG"
    ENV_VAR = "ENV_VAR"
    CMDLET_SET_POLICY = "CMDLET_SET_POLICY"
    REFLECTION_AUTH_MGR = "REFLECTION_AUTH_MGR"
    ADS_ZONE_STRIP = "ADS_ZONE_STRIP"
    STDIN_PIPELINE = "STDIN_PIPELINE"
    COMMAND_ARG = "COMMAND_ARG"
    ENCODED_COMMAND = "ENCODED_COMMAND"
    DOWNLOAD_CRADLE_MEMORY = "DOWNLOAD_CRADLE_MEMORY"
    REGISTRY_TAMPERING = "REGISTRY_TAMPERING"


class PolicySeverity(str, Enum):
    """Threat severity levels for policy findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class PolicyFinding:
    """Individual security finding identified during policy simulation."""
    technique: BypassTechnique
    severity: PolicySeverity
    target_level: ExecutionPolicyLevel
    target_scope: Optional[PolicyScope]
    description: str
    statement_index: int
    line_number: int
    matched_text: str
    requires_admin: bool = False
    blocked_by_gpo: bool = False
    mitigation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique.value,
            "severity": self.severity.value,
            "target_level": self.target_level.value,
            "target_scope": self.target_scope.value if self.target_scope else None,
            "description": self.description,
            "statement_index": self.statement_index,
            "line_number": self.line_number,
            "matched_text": self.matched_text,
            "requires_admin": self.requires_admin,
            "blocked_by_gpo": self.blocked_by_gpo,
            "mitigation": self.mitigation,
        }


@dataclass
class ScopeState:
    """PowerShell multi-scope execution policy state table."""
    machine_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED
    user_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED
    process: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED
    current_user: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED
    local_machine: ExecutionPolicyLevel = ExecutionPolicyLevel.UNDEFINED
    default_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.RESTRICTED

    def effective_policy(self) -> Tuple[ExecutionPolicyLevel, str]:
        """
        Determines the winning policy and active scope according to PowerShell precedence rules:
        MachinePolicy (GPO) > UserPolicy (GPO) > Process (Env/CLI) > CurrentUser (HKCU) > LocalMachine (HKLM) > Default.
        """
        if self.machine_policy != ExecutionPolicyLevel.UNDEFINED:
            return self.machine_policy, "MachinePolicy"
        if self.user_policy != ExecutionPolicyLevel.UNDEFINED:
            return self.user_policy, "UserPolicy"
        if self.process != ExecutionPolicyLevel.UNDEFINED:
            return self.process, "Process"
        if self.current_user != ExecutionPolicyLevel.UNDEFINED:
            return self.current_user, "CurrentUser"
        if self.local_machine != ExecutionPolicyLevel.UNDEFINED:
            return self.local_machine, "LocalMachine"
        return self.default_policy, "Default"

    def get_scope(self, scope: PolicyScope) -> ExecutionPolicyLevel:
        """Retrieves level configured for a specific scope."""
        if scope == PolicyScope.MACHINE_POLICY:
            return self.machine_policy
        if scope == PolicyScope.USER_POLICY:
            return self.user_policy
        if scope == PolicyScope.PROCESS:
            return self.process
        if scope == PolicyScope.CURRENT_USER:
            return self.current_user
        if scope == PolicyScope.LOCAL_MACHINE:
            return self.local_machine
        return ExecutionPolicyLevel.UNDEFINED

    def set_scope(self, scope: PolicyScope, level: ExecutionPolicyLevel) -> None:
        """Updates level for a specific scope."""
        if scope == PolicyScope.MACHINE_POLICY:
            self.machine_policy = level
        elif scope == PolicyScope.USER_POLICY:
            self.user_policy = level
        elif scope == PolicyScope.PROCESS:
            self.process = level
        elif scope == PolicyScope.CURRENT_USER:
            self.current_user = level
        elif scope == PolicyScope.LOCAL_MACHINE:
            self.local_machine = level

    def is_scope_blocked_by_gpo(self, scope: PolicyScope) -> bool:
        """Checks if a scope update is preempted and overridden by higher Group Policy."""
        if self.machine_policy != ExecutionPolicyLevel.UNDEFINED:
            return scope.precedence < PolicyScope.MACHINE_POLICY.precedence
        if self.user_policy != ExecutionPolicyLevel.UNDEFINED:
            return scope.precedence < PolicyScope.USER_POLICY.precedence
        return False

    def clone(self) -> "ScopeState":
        """Creates an independent clone of the scope state."""
        return ScopeState(
            machine_policy=self.machine_policy,
            user_policy=self.user_policy,
            process=self.process,
            current_user=self.current_user,
            local_machine=self.local_machine,
            default_policy=self.default_policy,
        )

    def to_dict(self) -> Dict[str, Any]:
        eff_lvl, eff_scope = self.effective_policy()
        return {
            "machine_policy": self.machine_policy.value,
            "user_policy": self.user_policy.value,
            "process": self.process.value,
            "current_user": self.current_user.value,
            "local_machine": self.local_machine.value,
            "default_policy": self.default_policy.value,
            "effective_level": eff_lvl.value,
            "effective_scope": eff_scope,
        }


@dataclass
class PolicyTransition:
    """Records state changes across statements during simulation."""
    step: int
    statement_snippet: str
    technique: BypassTechnique
    previous_level: ExecutionPolicyLevel
    previous_winning_scope: str
    new_level: ExecutionPolicyLevel
    new_winning_scope: str
    effective_changed: bool
    blocked_by_gpo: bool
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "statement_snippet": self.statement_snippet,
            "technique": self.technique.value,
            "previous_level": self.previous_level.value,
            "previous_winning_scope": self.previous_winning_scope,
            "new_level": self.new_level.value,
            "new_winning_scope": self.new_winning_scope,
            "effective_changed": self.effective_changed,
            "blocked_by_gpo": self.blocked_by_gpo,
            "description": self.description,
        }


@dataclass
class PolicySimulationSummary:
    """Comprehensive summary of policy simulation findings, transitions, and risk metrics."""
    initial_state: ScopeState
    final_state: ScopeState
    initial_effective: ExecutionPolicyLevel
    final_effective: ExecutionPolicyLevel
    bypass_detected: bool
    privilege_escalation_risk: bool
    findings: List[PolicyFinding] = field(default_factory=list)
    transitions: List[PolicyTransition] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "CLEAN"
    mitigations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_state": self.initial_state.to_dict(),
            "final_state": self.final_state.to_dict(),
            "initial_effective": self.initial_effective.value,
            "final_effective": self.final_effective.value,
            "bypass_detected": self.bypass_detected,
            "privilege_escalation_risk": self.privilege_escalation_risk,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "transitions_count": len(self.transitions),
            "transitions": [t.to_dict() for t in self.transitions],
            "mitigations": self.mitigations,
        }
