"""
Cryptographic engine for PowerShell SecureString parsing and decryption.
Implements standard PowerShell SecureString envelope parsing, AES-CBC decryption,
PKCS#7 unpadding, and buffer sanitization with pure-Python fallback support.
"""

import base64
import os
from typing import Any, Optional, Tuple, Union

# Attempt import of accelerated cryptography provider; fallback to pure-Python AES
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as crypto_padding

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


SECURE_STRING_GUID = "76492d1116743f0423413b16050a5345"


class SecureStringError(Exception):
    """Base exception for SecureString parsing and decryption failures."""
    pass


class InvalidSecureStringFormatError(SecureStringError):
    """Raised when the serialized SecureString envelope or payload format is malformed."""
    pass


class InvalidKeyLengthError(SecureStringError):
    """Raised when the encryption or decryption key length is not 16, 24, or 32 bytes."""
    pass


class SecureStringDecryptionError(SecureStringError):
    """Raised when ciphertext decryption or PKCS#7 unpadding fails."""
    pass


def zeroize_buffer(buf: Any) -> None:
    """
    Overwrites mutable byte/list buffers with zeroes to scrub sensitive data from memory.
    """
    if isinstance(buf, (bytearray, memoryview)):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, list):
        for i in range(len(buf)):
            buf[i] = 0


# =====================================================================
# Pure-Python AES-128 / 192 / 256 Implementation (Rijndael Specification)
# =====================================================================

_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _mul(a: int, b: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res


def _aes_key_expansion(key: bytes) -> Tuple[list, int]:
    nk = len(key) // 4
    nr = nk + 6
    w = list(key)
    i = nk
    while i < 4 * (nr + 1):
        temp = w[(i - 1) * 4 : i * 4]
        if i % nk == 0:
            temp = [_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
            temp[0] ^= _RCON[i // nk]
        elif nk > 6 and (i % nk == 4):
            temp = [_SBOX[temp[0]], _SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]]]
        prev = w[(i - nk) * 4 : (i - nk + 1) * 4]
        for j in range(4):
            w.append(prev[j] ^ temp[j])
        i += 1
    return w, nr


def _aes_inv_cipher_block(block: bytes, w: list, nr: int) -> bytes:
    state = list(block)
    for i in range(16):
        state[i] ^= w[nr * 16 + i]
    for r in range(nr - 1, 0, -1):
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
        state = [_INV_SBOX[b] for b in state]
        for i in range(16):
            state[i] ^= w[r * 16 + i]
        new_state = [0] * 16
        for c in range(4):
            col = state[c * 4 : (c + 1) * 4]
            new_state[c * 4] = _mul(col[0], 0x0E) ^ _mul(col[1], 0x0B) ^ _mul(col[2], 0x0D) ^ _mul(col[3], 0x09)
            new_state[c * 4 + 1] = _mul(col[0], 0x09) ^ _mul(col[1], 0x0E) ^ _mul(col[2], 0x0B) ^ _mul(col[3], 0x0D)
            new_state[c * 4 + 2] = _mul(col[0], 0x0D) ^ _mul(col[1], 0x09) ^ _mul(col[2], 0x0E) ^ _mul(col[3], 0x0B)
            new_state[c * 4 + 3] = _mul(col[0], 0x0B) ^ _mul(col[1], 0x0D) ^ _mul(col[2], 0x09) ^ _mul(col[3], 0x0E)
        state = new_state
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
    state = [_INV_SBOX[b] for b in state]
    for i in range(16):
        state[i] ^= w[i]
    return bytes(state)


def _aes_cipher_block(block: bytes, w: list, nr: int) -> bytes:
    state = list(block)
    for i in range(16):
        state[i] ^= w[i]
    for r in range(1, nr):
        state = [_SBOX[b] for b in state]
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
        new_state = [0] * 16
        for c in range(4):
            col = state[c * 4 : (c + 1) * 4]
            new_state[c * 4] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
            new_state[c * 4 + 1] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
            new_state[c * 4 + 2] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
            new_state[c * 4 + 3] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
        state = new_state
        for i in range(16):
            state[i] ^= w[r * 16 + i]
    state = [_SBOX[b] for b in state]
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
    for i in range(16):
        state[i] ^= w[nr * 16 + i]
    return bytes(state)


def _py_aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytearray:
    w, nr = _aes_key_expansion(key)
    plaintext = bytearray()
    prev = iv
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset : offset + 16]
        decrypted_block = _aes_inv_cipher_block(block, w, nr)
        plaintext.extend(bytes(x ^ y for x, y in zip(decrypted_block, prev)))
        prev = block
    zeroize_buffer(w)
    return plaintext


def _py_aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    w, nr = _aes_key_expansion(key)
    ciphertext = bytearray()
    prev = iv
    for offset in range(0, len(plaintext), 16):
        block = bytes(x ^ y for x, y in zip(plaintext[offset : offset + 16], prev))
        cipher_block = _aes_cipher_block(block, w, nr)
        ciphertext.extend(cipher_block)
        prev = cipher_block
    zeroize_buffer(w)
    return bytes(ciphertext)


# =====================================================================
# High-Level SecureString Serialization & Decryption API
# =====================================================================

def decrypt_secure_string(
    encrypted_str: str,
    key: bytes,
    use_pure_python: bool = False,
) -> str:
    """
    Parses and decrypts a standard PowerShell SecureString encrypted with an AES key.

    :param encrypted_str: Serialized SecureString starting with GUID header.
    :param key: 16, 24, or 32 bytes AES encryption key.
    :param use_pure_python: Force pure-Python AES decryption engine for fallback testing.
    :return: Decrypted Unicode plaintext string.
    """
    clean_str = encrypted_str.strip()
    if not clean_str.lower().startswith(SECURE_STRING_GUID.lower()):
        raise InvalidSecureStringFormatError("Missing standard PowerShell SecureString GUID header")

    if len(key) not in (16, 24, 32):
        raise InvalidKeyLengthError(f"Invalid AES key length: {len(key)} bytes (expected 16, 24, or 32)")

    b64_payload = clean_str[len(SECURE_STRING_GUID) :]
    try:
        raw_bytes = base64.b64decode(b64_payload)
        payload_text = raw_bytes.decode("utf-16le")
    except Exception as exc:
        raise InvalidSecureStringFormatError(f"Failed to decode SecureString base64 payload: {exc}") from exc

    parts = payload_text.split("|")
    if len(parts) != 3:
        raise InvalidSecureStringFormatError(f"Expected 3 envelope segments (<version>|<iv>|<ciphertext>), got {len(parts)}")

    version, iv_b64, ct_hex = parts
    try:
        iv = base64.b64decode(iv_b64)
    except Exception as exc:
        raise InvalidSecureStringFormatError(f"Failed to decode IV from base64: {exc}") from exc

    if len(iv) != 16:
        raise InvalidSecureStringFormatError(f"Invalid IV length: {len(iv)} bytes (expected 16)")

    try:
        ciphertext = bytes.fromhex(ct_hex)
    except Exception as exc:
        raise InvalidSecureStringFormatError(f"Failed to decode hex ciphertext: {exc}") from exc

    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise InvalidSecureStringFormatError(f"Ciphertext length must be a non-zero multiple of 16 (got {len(ciphertext)})")

    # Decrypt AES-CBC
    decrypted_buf = None
    try:
        if HAS_CRYPTOGRAPHY and not use_pure_python:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted_buf = bytearray(decryptor.update(ciphertext) + decryptor.finalize())
        else:
            decrypted_buf = _py_aes_cbc_decrypt(ciphertext, key, iv)
    except Exception as exc:
        if decrypted_buf:
            zeroize_buffer(decrypted_buf)
        raise SecureStringDecryptionError(f"AES-CBC decryption routine failed: {exc}") from exc

    # PKCS#7 Unpadding
    try:
        pad_len = decrypted_buf[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Padding byte value out of range")
        if decrypted_buf[-pad_len:] != bytearray([pad_len] * pad_len):
            raise ValueError("Padding byte mismatch")
        plaintext_bytes = decrypted_buf[:-pad_len]
        plaintext = plaintext_bytes.decode("utf-16le")
    except Exception as exc:
        raise SecureStringDecryptionError(f"PKCS#7 unpadding or UTF-16LE decoding failed: {exc}") from exc
    finally:
        if decrypted_buf:
            zeroize_buffer(decrypted_buf)

    return plaintext


def encrypt_secure_string(
    plaintext: str,
    key: bytes,
    iv: Optional[bytes] = None,
    use_pure_python: bool = False,
) -> str:
    """
    Encrypts a plaintext string into standard PowerShell SecureString envelope format.

    :param plaintext: Source string to encrypt.
    :param key: 16, 24, or 32 bytes AES encryption key.
    :param iv: Optional 16-byte IV. If None, generated via os.urandom(16).
    :param use_pure_python: Force pure-Python AES encryption engine.
    :return: Serialized SecureString envelope starting with GUID header.
    """
    if len(key) not in (16, 24, 32):
        raise InvalidKeyLengthError(f"Invalid AES key length: {len(key)} bytes (expected 16, 24, or 32)")

    if iv is None:
        iv = os.urandom(16)
    elif len(iv) != 16:
        raise ValueError(f"IV must be exactly 16 bytes (got {len(iv)})")

    raw_pt = bytearray(plaintext.encode("utf-16le"))
    pad_len = 16 - (len(raw_pt) % 16)
    raw_pt.extend([pad_len] * pad_len)

    try:
        if HAS_CRYPTOGRAPHY and not use_pure_python:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(bytes(raw_pt)) + encryptor.finalize()
        else:
            ciphertext = _py_aes_cbc_encrypt(bytes(raw_pt), key, iv)
    finally:
        zeroize_buffer(raw_pt)

    iv_b64 = base64.b64encode(iv).decode("ascii")
    ct_hex = ciphertext.hex()
    envelope = f"2|{iv_b64}|{ct_hex}"
    payload_b64 = base64.b64encode(envelope.encode("utf-16le")).decode("ascii")

    return f"{SECURE_STRING_GUID}{payload_b64}"
