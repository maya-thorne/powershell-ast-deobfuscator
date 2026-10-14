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
    SubexpressionNode,
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
from .subexpression_unwrapper import PowerShellSubexpressionUnwrapper
from .casing_normalizer import PowerShellCasingNormalizer
from .tokens import Token, TokenType
from .ast_exporter import (
    ASTExporter,
    export_ast_dot,
    export_ast_json,
    export_ast_mermaid,
    extract_ast_metrics,
)
from .ast_visualizer import ASTVisualizer, render_ast_tree
from .benchmark import (
    CorpusBenchmarkSummary,
    CorpusSample,
    SampleBenchmarkResult,
    calculate_entropy,
    calculate_fidelity_score,
    calculate_indicator_recall,
    calculate_size_reduction,
    check_ast_validity,
    detect_artifacts,
    get_corpus,
    get_corpus_by_category,
    get_sample,
    run_benchmark,
    run_sample,
    save_report,
    to_json_report,
    to_markdown_report,
    to_text_report,
)
from .type_accelerators import TypeAcceleratorRegistry
from .type_casting_resolver import PowerShellTypeCastingResolver

__version__ = "0.10.0"
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
    "PowerShellSubexpressionUnwrapper",
    "PowerShellCasingNormalizer",
    "ASTVisualizer",
    "render_ast_tree",
    "ASTExporter",
    "export_ast_mermaid",
    "export_ast_dot",
    "export_ast_json",
    "extract_ast_metrics",
    "CorpusSample",
    "get_corpus",
    "get_sample",
    "get_corpus_by_category",
    "SampleBenchmarkResult",
    "CorpusBenchmarkSummary",
    "calculate_entropy",
    "calculate_size_reduction",
    "detect_artifacts",
    "calculate_indicator_recall",
    "check_ast_validity",
    "calculate_fidelity_score",
    "run_sample",
    "run_benchmark",
    "to_text_report",
    "to_json_report",
    "to_markdown_report",
    "save_report",
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
    "SubexpressionNode",
    "UnaryOpNode",
    "DynamicMemberAccessNode",
    "DynamicMethodCallNode",
    "DynamicStaticMemberAccessNode",
    "IfStatementNode",
    "WhileStatementNode",
]




