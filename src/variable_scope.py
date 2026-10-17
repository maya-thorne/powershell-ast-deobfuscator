"""
PowerShell Variable Scope & Lifecycle Analysis Unified Facade.
Provides high-level interfaces for scope resolution, def-use chain tracking,
scoped constant propagation, and forensic scope telemetry export.
"""

import json
from typing import Any, Dict, Optional, Union

from .ast_nodes import ASTNode
from .lexer import PowerShellLexer
from .parser import PowerShellParser
from .scope_chain import PowerShellScopeChain
from .scope_models import (
    AccessKind,
    ScopeAnalysisSummary,
    ScopeFrame,
    ScopeSymbol,
    ScopeType,
    VarDefinition,
    VarRead,
)
from .variable_lifecycle_tracker import PowerShellVariableLifecycleTracker
from .variable_scope_inliner import PowerShellVariableScopeInliner


def analyze_scopes(
    script_or_ast: Union[str, ASTNode],
    symbols: Optional[Dict[str, Any]] = None,
) -> ScopeAnalysisSummary:
    """
    Parses (if string) and analyzes the variable scopes, def-use chains,
    shadowing anomalies, and dead assignments across the AST.
    """
    if isinstance(script_or_ast, str):
        tokens = PowerShellLexer(script_or_ast).tokenize()
        ast = PowerShellParser(tokens).parse()
    else:
        ast = script_or_ast

    tracker = PowerShellVariableLifecycleTracker(initial_symbols=symbols)
    return tracker.analyze(ast)


def inline_scoped_variables(
    script_or_ast: Union[str, ASTNode],
    symbols: Optional[Dict[str, Any]] = None,
    propagate_constants: bool = True,
    eliminate_dead_vars: bool = False,
) -> ASTNode:
    """
    Inlines scope-resolved constant variables and rewrites Get/Set-Variable cmdlets.
    """
    if isinstance(script_or_ast, str):
        tokens = PowerShellLexer(script_or_ast).tokenize()
        ast = PowerShellParser(tokens).parse()
    else:
        ast = script_or_ast

    inliner = PowerShellVariableScopeInliner(
        symbols=symbols,
        propagate_constants=propagate_constants,
        eliminate_dead_vars=eliminate_dead_vars,
    )
    return inliner.inline(ast)


def export_scope_json(summary: ScopeAnalysisSummary, indent: int = 2) -> str:
    """
    Exports a ScopeAnalysisSummary dataclass to a structured JSON string.
    """
    payload = {
        "telemetry": {
            "total_scopes": summary.total_scopes,
            "total_symbols": summary.total_symbols,
            "total_definitions": summary.total_definitions,
            "total_reads": summary.total_reads,
            "dead_assignments_count": summary.dead_assignments_count,
            "shadowed_symbols_count": summary.shadowed_symbols_count,
            "uninitialized_reads_count": summary.uninitialized_reads_count,
            "constant_candidates_count": summary.constant_candidates_count,
        },
        "scopes": summary.scopes,
        "symbols": summary.symbols_table,
        "dead_assignments": summary.dead_assignments,
        "shadowed_symbols": summary.shadowed_symbols,
        "uninitialized_reads": summary.uninitialized_reads,
        "constant_candidates": summary.constant_candidates,
    }
    return json.dumps(payload, indent=indent)


def to_scope_report(summary: ScopeAnalysisSummary) -> str:
    """
    Renders human-readable forensic summary report of variable scope and lifecycle telemetry.
    """
    lines = [
        "=== PowerShell Variable Scope & Lifecycle Analysis ===",
        f"Total Scopes: {summary.total_scopes} | Total Symbols: {summary.total_symbols}",
        f"Definitions: {summary.total_definitions} | Reads: {summary.total_reads}",
        f"Constant Candidates: {summary.constant_candidates_count} | Shadowed Symbols: {summary.shadowed_symbols_count}",
        f"Dead Assignments: {summary.dead_assignments_count} | Uninitialized Reads: {summary.uninitialized_reads_count}",
        "",
        "--- Scopes ---",
    ]
    for sc in summary.scopes:
        parent_info = f" (parent: {sc['parent_id']})" if sc["parent_id"] is not None else ""
        lines.append(f"  [{sc['scope_id']}] {sc['name']} ({sc['scope_type']}){parent_info} - {sc['symbols_count']} symbols")

    if summary.symbols_table:
        lines.append("")
        lines.append("--- Symbols Table ---")
        for sym in summary.symbols_table:
            const_info = f" [CONST: {sym['constant_value']}]" if sym["is_constant"] else ""
            dead_info = " [DEAD]" if sym["is_dead"] else ""
            shadow_info = " [SHADOWED]" if sym["is_shadowed"] else ""
            lines.append(f"  ${sym['name']} @ {sym['scope']} (defs: {sym['definitions']}, reads: {sym['reads']}){const_info}{dead_info}{shadow_info}")

    if summary.dead_assignments:
        lines.append("")
        lines.append("--- Dead Assignments ---")
        for d in summary.dead_assignments:
            val_str = f" = {d['value']}" if d['value'] is not None else ""
            lines.append(f"  [Stmt {d['statement_index']}] ${d['variable']} in {d['scope']}{val_str}")

    if summary.shadowed_symbols:
        lines.append("")
        lines.append("--- Shadowed Symbols ---")
        for s in summary.shadowed_symbols:
            lines.append(f"  ${s['variable']} in {s['scope']} shadows scope [{s['shadowed_scope_id']}]")

    return "\n".join(lines)


__all__ = [
    "ScopeType",
    "AccessKind",
    "VarRead",
    "VarDefinition",
    "ScopeSymbol",
    "ScopeFrame",
    "ScopeAnalysisSummary",
    "PowerShellScopeChain",
    "PowerShellVariableLifecycleTracker",
    "PowerShellVariableScopeInliner",
    "analyze_scopes",
    "inline_scoped_variables",
    "export_scope_json",
    "to_scope_report",
]
