"""
PowerShell SecureString & ConvertTo-SecureString Emulation Engine.
Unified facade exposing cryptographic operations, key extraction, and AST reduction.
"""

from .secure_string_crypto import (
    AES_BLOCK_SIZE,
    POWERSHELL_V2_MAGIC_GUID,
    InvalidKeyLengthError,
    InvalidSecureStringFormatError,
    PurePythonRijndael,
    SecureStringDecryptionError,
    SecureStringError,
    decrypt_secure_string,
    encrypt_secure_string,
    zeroize_buffer,
)
from .secure_string_reducer import PowerShellSecureStringReducer
from .static_key_extractor import StaticKeyExtractor

# Backward-compatibility alias
SecureStringEmulator = PowerShellSecureStringReducer

__all__ = [
    "POWERSHELL_V2_MAGIC_GUID",
    "AES_BLOCK_SIZE",
    "SecureStringError",
    "InvalidSecureStringFormatError",
    "InvalidKeyLengthError",
    "SecureStringDecryptionError",
    "PurePythonRijndael",
    "zeroize_buffer",
    "decrypt_secure_string",
    "encrypt_secure_string",
    "StaticKeyExtractor",
    "PowerShellSecureStringReducer",
    "SecureStringEmulator",
]
