"""
PowerShell AST Deobfuscator & Compiler-Grade Syntax Engine.
Engineered by Maya Thorne.
"""

from .ast_nodes import (
    ASTNode,
    CommandNode,
    DynamicMemberAccessNode,
    DynamicMethodCallNode,
    DynamicStaticMemberAccessNode,
    IfStatementNode,
    IndexAccessNode,
    ScriptBlockNode,
    StringLiteralNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from .deobfuscator_engine import PowerShellDeobfuscator
from .environment_inliner import PowerShellEnvironmentInliner
from .lexer import PowerShellLexer
from .normalizer import PowerShellNormalizer
from .parser import PowerShellParser
from .pipeline_optimizer import PowerShellPipelineOptimizer
from .reflection_unwrapper import PowerShellReflectionUnwrapper
from .scriptblock_simplifier import PowerShellScriptBlockSimplifier
from .secure_string_crypto import (
    InvalidKeyLengthError,
    InvalidSecureStringFormatError,
    SecureStringDecryptionError,
    SecureStringError,
    decrypt_secure_string,
    encrypt_secure_string,
    zeroize_buffer,
)
from .secure_string_reducer import PowerShellSecureStringReducer
from .static_key_extractor import StaticKeyExtractor
from .tokens import Token, TokenType
from .ast_exporter import (
    ASTExporter,
    export_ast_dot,
    export_ast_json,
    export_ast_mermaid,
    extract_ast_metrics,
)
from .ast_visualizer import ASTVisualizer, render_ast_tree
from .type_accelerators import TypeAcceleratorRegistry
from .type_casting_resolver import PowerShellTypeCastingResolver

__version__ = "0.7.0"
__all__ = [
    "TokenType",
    "Token",
    "PowerShellLexer",
    "PowerShellParser",
    "PowerShellNormalizer",
    "PowerShellDeobfuscator",
    "PowerShellEnvironmentInliner",
    "PowerShellReflectionUnwrapper",
    "PowerShellPipelineOptimizer",
    "PowerShellScriptBlockSimplifier",
    "ASTVisualizer",
    "render_ast_tree",
    "ASTExporter",
    "export_ast_mermaid",
    "export_ast_dot",
    "export_ast_json",
    "extract_ast_metrics",
    "decrypt_secure_string",
    "encrypt_secure_string",
    "zeroize_buffer",
    "SecureStringError",
    "InvalidSecureStringFormatError",
    "InvalidKeyLengthError",
    "SecureStringDecryptionError",
    "StaticKeyExtractor",
    "PowerShellSecureStringReducer",
    "TypeAcceleratorRegistry",
    "PowerShellTypeCastingResolver",
    "ASTNode",
    "ScriptBlockNode",
    "CommandNode",
    "StringLiteralNode",
    "VariableNode",
    "IndexAccessNode",
    "UnaryOpNode",
    "DynamicMemberAccessNode",
    "DynamicMethodCallNode",
    "DynamicStaticMemberAccessNode",
    "IfStatementNode",
    "WhileStatementNode",
]



