"""
PowerShell AST Deobfuscator & Compiler-Grade Syntax Engine.
Engineered by Maya Thorne.
"""

from .ast_nodes import (
    ASTNode,
    CommandNode,
    IndexAccessNode,
    ScriptBlockNode,
    StringLiteralNode,
    UnaryOpNode,
    VariableNode,
)
from .deobfuscator_engine import PowerShellDeobfuscator
from .environment_inliner import PowerShellEnvironmentInliner
from .lexer import PowerShellLexer
from .normalizer import PowerShellNormalizer
from .parser import PowerShellParser
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
from .type_accelerators import TypeAcceleratorRegistry
from .type_casting_resolver import PowerShellTypeCastingResolver

__version__ = "0.4.0"
__all__ = [
    "TokenType",
    "Token",
    "PowerShellLexer",
    "PowerShellParser",
    "PowerShellNormalizer",
    "PowerShellDeobfuscator",
    "PowerShellEnvironmentInliner",
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
]

