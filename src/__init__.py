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
    ForEachStatementNode,
    ForStatementNode,
    IfStatementNode,
    IndexAccessNode,
    ScriptBlockNode,
    StringLiteralNode,
    SubexpressionNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from .bitwise_folding_engine import PowerShellBitwiseFoldingEngine
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
from .webclient_tracer import (
    PowerShellWebClientTracer,
    RemotePayloadTarget,
    carve_all_urls,
    extract_download_urls,
    trace_webclient,
)
from .xor_loop_decryptor import PowerShellXorLoopDecryptor
from .iex_unwrapper import (
    IEXLayer,
    IEXUnwrapResult,
    PowerShellIEXUnwrapper,
    peel_iex_string,
    trace_iex_layers,
    unwrap_iex,
)
from .amsi_etw_signatures import (
    BUILTIN_SIGNATURES,
    DEFAULT_RULESET,
    AmsiEtwFinding,
    AmsiEtwRuleSet,
    BypassCategory,
    BypassSeverity,
    BypassSignature,
    TargetSystem,
)
from .amsi_etw_detector import (
    PowerShellAmsiEtwDetector,
    SanitizationResult,
    detect_amsi_etw,
    neutralize_amsi_etw,
)
from .amsi_etw_sanitizer import AmsiEtwSanitizer
from .rule_models import (
    IndicatorCategory,
    MitreAttackCatalog,
    RuleMetadata,
    RuleSeverity,
    RuleStatus,
    RuleSynthesisOptions,
    ThreatIndicator,
)
from .indicator_extractor import PowerShellIndicatorExtractor
from .yara_generator import YaraRuleGenerator
from .sigma_generator import SigmaRuleGenerator
from .threat_rule_generator import (
    ThreatRuleGenerator,
    generate_sigma_rule,
    generate_threat_rules,
    generate_yara_rule,
)
from .variable_scope import (
    AccessKind,
    PowerShellScopeChain,
    PowerShellVariableLifecycleTracker,
    PowerShellVariableScopeInliner,
    ScopeAnalysisSummary,
    ScopeFrame,
    ScopeSymbol,
    ScopeType,
    VarDefinition,
    VarRead,
    analyze_scopes,
    export_scope_json,
    inline_scoped_variables,
    to_scope_report,
)
from .policy_models import (
    BypassTechnique,
    ExecutionPolicyLevel,
    PolicyFinding,
    PolicyScope,
    PolicySeverity,
    PolicySimulationSummary,
    PolicyTransition,
    ScopeState,
)
from .policy_reducer import PowerShellPolicyReducer
from .policy_simulator import PowerShellPolicySimulator
from .execution_policy import (
    detect_policy_bypasses,
    export_policy_json,
    neutralize_policy_bypasses,
    parse_cli_policy_args,
    simulate_execution_policy,
    to_policy_report,
)
from .fuzzing import (
    FuzzExecutionResult,
    FuzzMutationRecord,
    FuzzSeverity,
    FuzzStatus,
    FuzzSummary,
    FuzzTestCase,
    MutationStrategy,
    PowerShellFuzzRunner,
    PowerShellScriptMutator,
    fuzz_script,
    mutate_script,
    run_fuzz_harness,
)
from .batch_models import (
    BatchScanOptions,
    BatchSummary,
    FileScanResult,
    RiskTier,
    ScanStatus,
)
from .batch_scanner import PowerShellBatchScanner
from .batch_runner import PowerShellBatchRunner
from .batch import (
    run_batch_cli,
    scan_directory,
    scan_files,
)

__version__ = "0.20.0"
__all__ = [
    "ScanStatus",
    "RiskTier",
    "FileScanResult",
    "BatchScanOptions",
    "BatchSummary",
    "PowerShellBatchScanner",
    "PowerShellBatchRunner",
    "scan_directory",
    "scan_files",
    "run_batch_cli",
    "MutationStrategy",
    "FuzzStatus",
    "FuzzSeverity",
    "FuzzMutationRecord",
    "FuzzTestCase",
    "FuzzExecutionResult",
    "FuzzSummary",
    "PowerShellScriptMutator",
    "PowerShellFuzzRunner",
    "run_fuzz_harness",
    "mutate_script",
    "fuzz_script",
    "ExecutionPolicyLevel",
    "PolicyScope",
    "BypassTechnique",
    "PolicySeverity",
    "PolicyFinding",
    "ScopeState",
    "PolicyTransition",
    "PolicySimulationSummary",
    "PowerShellPolicySimulator",
    "PowerShellPolicyReducer",
    "simulate_execution_policy",
    "detect_policy_bypasses",
    "parse_cli_policy_args",
    "neutralize_policy_bypasses",
    "to_policy_report",
    "export_policy_json",
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
    "ThreatIndicator",
    "IndicatorCategory",
    "RuleSeverity",
    "RuleStatus",
    "RuleMetadata",
    "RuleSynthesisOptions",
    "MitreAttackCatalog",
    "PowerShellIndicatorExtractor",
    "YaraRuleGenerator",
    "SigmaRuleGenerator",
    "ThreatRuleGenerator",
    "generate_yara_rule",
    "generate_sigma_rule",
    "generate_threat_rules",
    "TokenType",
    "Token",
    "PowerShellLexer",
    "PowerShellParser",
    "PowerShellNormalizer",
    "PowerShellDeobfuscator",
    "PowerShellBitwiseFoldingEngine",
    "PowerShellXorLoopDecryptor",
    "PowerShellEnvironmentInliner",
    "PowerShellReflectionUnwrapper",
    "PowerShellPipelineOptimizer",
    "PowerShellScriptBlockSimplifier",
    "PowerShellSubexpressionUnwrapper",
    "PowerShellCasingNormalizer",
    "PowerShellIEXUnwrapper",
    "IEXLayer",
    "IEXUnwrapResult",
    "unwrap_iex",
    "trace_iex_layers",
    "peel_iex_string",
    "PowerShellAmsiEtwDetector",
    "AmsiEtwSanitizer",
    "SanitizationResult",
    "detect_amsi_etw",
    "neutralize_amsi_etw",
    "BypassCategory",
    "TargetSystem",
    "BypassSeverity",
    "BypassSignature",
    "AmsiEtwFinding",
    "AmsiEtwRuleSet",
    "BUILTIN_SIGNATURES",
    "DEFAULT_RULESET",
    "PowerShellWebClientTracer",
    "RemotePayloadTarget",
    "trace_webclient",
    "carve_all_urls",
    "extract_download_urls",
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
    "ForStatementNode",
    "ForEachStatementNode",
]




