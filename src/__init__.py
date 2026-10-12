"""
PowerShell AST Deobfuscator & Compiler-Grade Syntax Engine.
Engineered by Maya Thorne.
"""

from .ast_nodes import ASTNode, CommandNode, ScriptBlockNode, StringLiteralNode, VariableNode
from .deobfuscator_engine import PowerShellDeobfuscator
from .lexer import PowerShellLexer
from .normalizer import PowerShellNormalizer
from .parser import PowerShellParser
from .tokens import Token, TokenType

__version__ = "0.1.0"
__all__ = [
    "TokenType",
    "Token",
    "PowerShellLexer",
    "PowerShellParser",
    "PowerShellNormalizer",
    "PowerShellDeobfuscator",
    "ASTNode",
    "ScriptBlockNode",
    "CommandNode",
    "StringLiteralNode",
    "VariableNode",
]
