"""
PowerShell AST Deobfuscation Fuzzing Models & Telemetry Schema.
Defines mutation strategies, test case schemas, execution results, and summary telemetry.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from typing import Any, Dict, List, Optional


class MutationStrategy(str, Enum):
    """Supported mutation and stress fuzzing strategies."""
    BACKTICK_INJECTION = "backtick_injection"
    CASE_SCRAMBLE = "case_scramble"
    WHITESPACE_MUTATION = "whitespace_mutation"
    COMMENT_INJECTION = "comment_injection"
    NESTING_STRESS = "nesting_stress"
    FORMAT_STRING_SHUFFLE = "format_string_shuffle"
    STRING_SPLIT_CONCAT = "string_split_concat"
    ARRAY_MANGLE = "array_mangle"
    TYPE_MANGLE = "type_mangle"
    UNICODE_EDGE = "unicode_edge"
    SYNTAX_CORRUPTION = "syntax_corruption"
    DECOY_INJECTION = "decoy_injection"
    RANGE_STRESS = "range_stress"
    PIPE_CHAIN = "pipe_chain"
    RECURSIVE_ENCODING = "recursive_encoding"
    VARIABLE_SHADOW = "variable_shadow"


class FuzzStatus(str, Enum):
    """Outcome classification of an individual fuzz test execution."""
    PASS = "pass"
    HANDLED_SYNTAX_ERROR = "handled_syntax_error"
    UNEXPECTED_CRASH = "unexpected_crash"
    TIMEOUT = "timeout"
    REGRESSION = "regression"


class FuzzSeverity(str, Enum):
    """Severity rating for fuzzing findings and exceptions."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FuzzMutationRecord:
    """Record of a single mutation applied to a script."""
    strategy: MutationStrategy
    description: str
    offset: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy": self.strategy.value if isinstance(self.strategy, MutationStrategy) else str(self.strategy),
            "description": self.description,
            "offset": self.offset,
            "metadata": self.metadata,
        }


@dataclass
class FuzzTestCase:
    """Represents a generated or mutated test case input."""
    test_id: str
    seed: int
    base_name: str
    original_code: str
    mutated_code: str
    mutations: List[FuzzMutationRecord] = field(default_factory=list)
    target_strategies: List[MutationStrategy] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "seed": self.seed,
            "base_name": self.base_name,
            "original_code": self.original_code,
            "mutated_code": self.mutated_code,
            "mutations": [m.to_dict() for m in self.mutations],
            "target_strategies": [s.value if isinstance(s, MutationStrategy) else str(s) for s in self.target_strategies],
        }


@dataclass
class FuzzExecutionResult:
    """Detailed telemetry and diagnostics resulting from running a fuzz test case."""
    test_id: str
    seed: int
    status: FuzzStatus
    duration_ms: float
    mutations_applied: List[str]
    original_length: int
    mutated_length: int
    deobfuscated_code: Optional[str] = None
    ast_node_count: int = 0
    ast_depth: int = 0
    is_idempotent: bool = True
    error_message: Optional[str] = None
    exception_type: Optional[str] = None
    traceback_snippet: Optional[str] = None
    shrunk_reproducer: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "seed": self.seed,
            "status": self.status.value if isinstance(self.status, FuzzStatus) else str(self.status),
            "duration_ms": round(self.duration_ms, 3),
            "mutations_applied": self.mutations_applied,
            "original_length": self.original_length,
            "mutated_length": self.mutated_length,
            "deobfuscated_code": self.deobfuscated_code,
            "ast_node_count": self.ast_node_count,
            "ast_depth": self.ast_depth,
            "is_idempotent": self.is_idempotent,
            "error_message": self.error_message,
            "exception_type": self.exception_type,
            "traceback_snippet": self.traceback_snippet,
            "shrunk_reproducer": self.shrunk_reproducer,
        }


@dataclass
class FuzzSummary:
    """Aggregated metrics and health indicators across a fuzzing harness execution run."""
    total_cases: int
    passed: int
    handled_syntax_errors: int
    unexpected_crashes: int
    regressions: int
    timeouts: int
    total_duration_ms: float
    strategy_counts: Dict[str, int] = field(default_factory=dict)
    results: List[FuzzExecutionResult] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        """Percentage of test cases that executed cleanly without crashes (pass + handled errors)."""
        if self.total_cases == 0:
            return 100.0
        safe_runs = self.passed + self.handled_syntax_errors
        return round((safe_runs / self.total_cases) * 100.0, 2)

    @property
    def clean_pass_rate(self) -> float:
        """Percentage of test cases that parsed and deobfuscated to a valid AST cleanly."""
        if self.total_cases == 0:
            return 100.0
        return round((self.passed / self.total_cases) * 100.0, 2)

    @property
    def crashes(self) -> List[FuzzExecutionResult]:
        """List of executions resulting in unexpected crashes or regressions."""
        return [r for r in self.results if r.status in (FuzzStatus.UNEXPECTED_CRASH, FuzzStatus.REGRESSION)]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cases": self.total_cases,
            "passed": self.passed,
            "handled_syntax_errors": self.handled_syntax_errors,
            "unexpected_crashes": self.unexpected_crashes,
            "regressions": self.regressions,
            "timeouts": self.timeouts,
            "pass_rate": self.pass_rate,
            "clean_pass_rate": self.clean_pass_rate,
            "total_duration_ms": round(self.total_duration_ms, 3),
            "strategy_counts": self.strategy_counts,
            "crashes_count": len(self.crashes),
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2, ensure_ascii: bool = True) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=ensure_ascii)
