"""
PowerShell AST Deobfuscator & Compiler-Grade Syntax Engine.
Engineered by Maya Thorne.
"""

from .ast_nodes import ASTNode, CommandNode, ScriptBlockNode, StringLiteralNode, VariableNode
from .deobfuscator_engine import PowerShellDeobfuscator
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

__version__ = "0.2.0"
__all__ = [
    "TokenType",
    "Token",
    "PowerShellLexer",
    "PowerShellParser",
    "PowerShellNormalizer",
    "PowerShellDeobfuscator",
    "decrypt_secure_string",
    "encrypt_secure_string",
    "zeroize_buffer",
    "SecureStringError",
    "InvalidSecureStringFormatError",
    "InvalidKeyLengthError",
    "SecureStringDecryptionError",
    "StaticKeyExtractor",
    "PowerShellSecureStringReducer",
    "ASTNode",
    "ScriptBlockNode",
    "CommandNode",
    "StringLiteralNode",
    "VariableNode",
]

