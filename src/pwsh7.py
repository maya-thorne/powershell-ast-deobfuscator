"""
PowerShell 7+ (Core / pwsh) Unified Public Facade.
Provides high-level APIs for AST folding, nullness analysis,
truthiness evaluation, and dead-code elimination.
"""

from typing import Any, Dict, Optional

from .ast_nodes import (
    ASTNode,
    CoalesceAssignmentNode,
    CoalesceExpressionNode,
    TernaryExpressionNode,
)
from .pwsh7_reducer import PowerShell7Reducer


def fold_pwsh7_operators(
    node: ASTNode,
    symbols: Optional[Dict[str, Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> ASTNode:
    """
    Convenience helper to fold PowerShell 7+ ternary and null-coalescing operators
    across an AST hierarchy using static symbol context.
    """
    reducer = PowerShell7Reducer(symbols=symbols, env=env)
    return reducer.reduce(node)


def is_statically_truthy(
    node: ASTNode,
    symbols: Optional[Dict[str, Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> Optional[bool]:
    """
    Evaluates whether an AST node is statically truthy or falsy.
    Returns True, False, or None if undecidable.
    """
    reducer = PowerShell7Reducer(symbols=symbols, env=env)
    return reducer.evaluate_truthiness(node)


def is_statically_null(
    node: ASTNode,
    symbols: Optional[Dict[str, Any]] = None,
    env: Optional[Dict[str, str]] = None,
) -> Optional[bool]:
    """
    Evaluates whether an AST node is statically $null or guaranteed non-null.
    Returns True for null, False for non-null, or None if undecidable.
    """
    reducer = PowerShell7Reducer(symbols=symbols, env=env)
    return reducer.evaluate_nullness(node)


__all__ = [
    "PowerShell7Reducer",
    "CoalesceAssignmentNode",
    "CoalesceExpressionNode",
    "TernaryExpressionNode",
    "fold_pwsh7_operators",
    "is_statically_truthy",
    "is_statically_null",
]
