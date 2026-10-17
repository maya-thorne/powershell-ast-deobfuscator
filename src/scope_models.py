"""
PowerShell Variable Scope & Lifecycle Data Models.
Defines scope types, variable access modes, symbol table entries,
scope frame hierarchy, and analysis summary telemetry.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .ast_nodes import ASTNode


class ScopeType(Enum):
    """PowerShell scope levels."""
    GLOBAL = "global"
    SCRIPT = "script"
    LOCAL = "local"
    PRIVATE = "private"
    FUNCTION = "function"
    SCRIPT_BLOCK = "scriptblock"
    USING = "using"


class AccessKind(Enum):
    """Kind of access on a variable symbol."""
    READ = "read"
    WRITE = "write"
    DECLARATION = "declaration"
    CLEAR = "clear"
    REMOVE = "remove"


@dataclass
class VarRead:
    """Represents a variable read/usage site in the AST."""
    read_id: int
    variable_name: str
    requested_scope: Optional[str] = None
    resolved_scope_id: Optional[int] = None
    ast_node: Optional[ASTNode] = None
    statement_index: int = 0
    reaching_definition_id: Optional[int] = None
    is_uninitialized: bool = False


@dataclass
class VarDefinition:
    """Represents a variable definition/assignment site in the AST."""
    definition_id: int
    variable_name: str
    scope_type: ScopeType
    scope_id: int
    ast_node: Optional[ASTNode] = None
    value: Any = None
    is_constant: bool = False
    statement_index: int = 0
    is_dead: bool = False
    reader_ids: List[int] = field(default_factory=list)


@dataclass
class ScopeSymbol:
    """Represents a unique variable symbol tracked within a specific scope frame."""
    name: str  # Lowercase normalized key
    original_name: str  # Preserved original casing
    scope_id: int
    scope_type: ScopeType
    is_private: bool = False
    is_constant: bool = False
    constant_value: Any = None
    constant_node: Optional[ASTNode] = None
    definitions: List[VarDefinition] = field(default_factory=list)
    reads: List[VarRead] = field(default_factory=list)
    is_shadowed: bool = False
    shadowed_scope_id: Optional[int] = None
    is_dead: bool = False
    is_uninitialized: bool = False
    data_type: Optional[str] = None

    @property
    def total_reads(self) -> int:
        return len(self.reads)

    @property
    def total_definitions(self) -> int:
        return len(self.definitions)

    @property
    def live_range(self) -> Tuple[int, int]:
        """Calculates statement span (first def/use to last def/use)."""
        indices: List[int] = []
        for d in self.definitions:
            indices.append(d.statement_index)
        for r in self.reads:
            indices.append(r.statement_index)
        if not indices:
            return (0, 0)
        return (min(indices), max(indices))


@dataclass
class ScopeFrame:
    """Represents a single lexical or runtime scope level in the scope hierarchy."""
    scope_id: int
    scope_type: ScopeType
    name: str
    parent: Optional["ScopeFrame"] = None
    children: List["ScopeFrame"] = field(default_factory=list)
    symbols: Dict[str, ScopeSymbol] = field(default_factory=dict)

    def get_symbol(self, name: str) -> Optional[ScopeSymbol]:
        """Looks up a symbol strictly within this scope frame."""
        return self.symbols.get(name.lower())

    def define_symbol(
        self,
        name: str,
        original_name: Optional[str] = None,
        is_private: bool = False,
        data_type: Optional[str] = None,
    ) -> ScopeSymbol:
        """Creates or retrieves a symbol in this frame."""
        key = name.lower()
        if key not in self.symbols:
            orig = original_name if original_name is not None else name
            self.symbols[key] = ScopeSymbol(
                name=key,
                original_name=orig,
                scope_id=self.scope_id,
                scope_type=self.scope_type,
                is_private=is_private,
                data_type=data_type,
            )
        return self.symbols[key]


@dataclass
class ScopeAnalysisSummary:
    """Forensic summary of variable scope and lifecycle telemetry."""
    total_scopes: int = 0
    total_symbols: int = 0
    total_definitions: int = 0
    total_reads: int = 0
    dead_assignments_count: int = 0
    shadowed_symbols_count: int = 0
    uninitialized_reads_count: int = 0
    constant_candidates_count: int = 0
    scopes: List[Dict[str, Any]] = field(default_factory=list)
    symbols_table: List[Dict[str, Any]] = field(default_factory=list)
    dead_assignments: List[Dict[str, Any]] = field(default_factory=list)
    shadowed_symbols: List[Dict[str, Any]] = field(default_factory=list)
    uninitialized_reads: List[Dict[str, Any]] = field(default_factory=list)
    constant_candidates: List[Dict[str, Any]] = field(default_factory=list)
