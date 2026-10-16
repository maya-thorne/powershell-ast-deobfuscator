"""
Core in-memory stream decompressor engine for Windows PowerShell scripts.
Supports GzipStream, DeflateStream (raw RFC 1951 and zlib RFC 1950), and BrotliStream,
with automated format probing, multi-encoding detection, and memory scrubbing.
"""

import base64
from collections import Counter
import gzip
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import zlib

try:
    import brotli
    _HAS_BROTLI = True
except ImportError:
    brotli = None
    _HAS_BROTLI = False

from .compression_models import CompressionType, StreamEncoding
from .secure_string_crypto import zeroize_buffer


def calculate_entropy(data: Union[str, bytes]) -> float:
    """
    Calculates Shannon entropy in bits per symbol (0.0 to 8.0).
    Higher entropy indicates compressed, encrypted, or Base64-encoded payloads.
    """
    if not data:
        return 0.0
    if isinstance(data, str):
        byte_data = data.encode("utf-8", errors="ignore")
    else:
        byte_data = data
    if not byte_data:
        return 0.0
    length = len(byte_data)
    counts = Counter(byte_data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def parse_base64_stream(b64_str: str) -> Optional[bytes]:
    """
    Cleans, normalizes, pads, and decodes Base64 encoded stream bytes.
    Handles quote stripping, backtick escapes, and missing padding.
    """
    if not b64_str:
        return None

    clean = b64_str.strip()
    if (clean.startswith("'") and clean.endswith("'")) or (clean.startswith('"') and clean.endswith('"')):
        clean = clean[1:-1].strip()
    clean = clean.replace("`", "")
    clean = re.sub(r"[\s\r\n\t]+", "", clean)

    if len(clean) < 4:
        return None

    normalized = clean.replace("-", "+").replace("_", "/")
    rem = len(normalized) % 4
    if rem == 2:
        normalized += "=="
    elif rem == 3:
        normalized += "="
    elif rem == 1:
        normalized = normalized[:-1]

    try:
        return base64.b64decode(normalized, validate=False)
    except Exception:
        try:
            return base64.urlsafe_b64decode(normalized)
        except Exception:
            return None


def decompress_stream_bytes(
    data: bytes,
    preferred_type: Optional[CompressionType] = None,
) -> Tuple[Optional[bytes], CompressionType]:
    """
    Decompresses raw bytes using the specified or auto-detected compression algorithm.
    Accurately handles:
    1. GzipStream: RFC 1952 header (0x1f 0x8b) via gzip or zlib wbits=31.
    2. DeflateStream: RFC 1951 raw deflate (standard .NET output) via zlib wbits=-15.
    3. DeflateStream: RFC 1950 zlib-wrapped deflate (0x78 header) via zlib wbits=15.
    4. BrotliStream: RFC 7932 brotli stream if runtime package is available.
    """
    if not data or len(data) == 0:
        return None, CompressionType.UNKNOWN

    # 1. Probe for GZIP magic header (0x1F, 0x8B)
    is_gzip_magic = len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B

    # Priority list of decompressors based on hint or detection
    candidates: List[Tuple[CompressionType, Any]] = []

    if preferred_type == CompressionType.GZIP or (preferred_type is None and is_gzip_magic):
        candidates.append((CompressionType.GZIP, lambda d: gzip.decompress(d)))
        candidates.append((CompressionType.GZIP, lambda d: zlib.decompress(d, zlib.MAX_WBITS | 16)))
        candidates.append((CompressionType.DEFLATE, lambda d: zlib.decompress(d, -zlib.MAX_WBITS)))
        candidates.append((CompressionType.DEFLATE, lambda d: zlib.decompress(d, zlib.MAX_WBITS)))
    elif preferred_type == CompressionType.DEFLATE:
        # Standard .NET DeflateStream writes raw DEFLATE without headers
        candidates.append((CompressionType.DEFLATE, lambda d: zlib.decompress(d, -zlib.MAX_WBITS)))
        candidates.append((CompressionType.DEFLATE, lambda d: zlib.decompress(d, zlib.MAX_WBITS)))
        candidates.append((CompressionType.GZIP, lambda d: gzip.decompress(d)))
    elif preferred_type == CompressionType.BROTLI:
        if _HAS_BROTLI:
            candidates.append((CompressionType.BROTLI, lambda d: brotli.decompress(d)))
        candidates.append((CompressionType.DEFLATE, lambda d: zlib.decompress(d, -zlib.MAX_WBITS)))
        candidates.append((CompressionType.GZIP, lambda d: gzip.decompress(d)))
    else:
        # Auto-detect without explicit hint
        if is_gzip_magic:
            candidates.append((CompressionType.GZIP, lambda d: gzip.decompress(d)))
            candidates.append((CompressionType.GZIP, lambda d: zlib.decompress(d, zlib.MAX_WBITS | 16)))
        # Raw deflate (most common in PowerShell DeflateStream payloads)
        candidates.append((CompressionType.DEFLATE, lambda d: zlib.decompress(d, -zlib.MAX_WBITS)))
        # Zlib-wrapped deflate
        candidates.append((CompressionType.DEFLATE, lambda d: zlib.decompress(d, zlib.MAX_WBITS)))
        # Gzip fallback
        candidates.append((CompressionType.GZIP, lambda d: gzip.decompress(d)))
        if _HAS_BROTLI:
            candidates.append((CompressionType.BROTLI, lambda d: brotli.decompress(d)))

    for c_type, decompress_fn in candidates:
        try:
            decompressed = decompress_fn(data)
            if decompressed is not None and len(decompressed) > 0:
                return decompressed, c_type
        except Exception:
            continue

    return None, CompressionType.UNKNOWN


def decode_stream_bytes(
    data: bytes,
    encoding_hint: Optional[str] = None,
) -> Tuple[Optional[str], str]:
    """
    Decodes decompressed payload bytes into a Unicode string with multi-encoding heuristics.
    Detects UTF-8 / UTF-16LE / UTF-16BE BOMs, alternating zero bytes (UTF-16LE without BOM),
    and honors encoding hints ([System.Text.Encoding]::UTF8, Unicode, ASCII).
    Scans for null-byte density and gracefully falls back to Latin-1 for 100% lossless decoding.
    """
    if not data:
        return None, "empty"

    # 1. BOM detection
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data[3:].decode("utf-8"), "utf-8-bom"
        except Exception:
            pass
    elif data.startswith(b"\xff\xfe"):
        try:
            return data[2:].decode("utf-16le"), "utf-16le-bom"
        except Exception:
            pass
    elif data.startswith(b"\xfe\xff"):
        try:
            return data[2:].decode("utf-16be"), "utf-16be-bom"
        except Exception:
            pass

    # 2. Check explicit encoding hint
    if encoding_hint:
        clean_hint = encoding_hint.lower().replace("-", "").replace("_", "")
        if "utf8" in clean_hint:
            try:
                return data.decode("utf-8"), "utf-8"
            except Exception:
                pass
        elif "unicode" in clean_hint or "utf16le" in clean_hint or "utf16" in clean_hint:
            try:
                return data.decode("utf-16le"), "utf-16le"
            except Exception:
                pass
        elif "ascii" in clean_hint:
            try:
                return data.decode("ascii"), "ascii"
            except Exception:
                pass

    # 3. Heuristic for UTF-16LE without BOM (PowerShell scripts with wide characters)
    # Check if high bytes in odd positions are predominantly zero
    if len(data) >= 4 and len(data) % 2 == 0:
        odd_zeros = data[1::2].count(0)
        if odd_zeros > (len(data) // 4):
            try:
                text = data.decode("utf-16le")
                # Ensure the decoded text contains mostly printable characters
                printable_count = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
                if printable_count / len(text) > 0.85:
                    return text, "utf-16le"
            except Exception:
                pass

    # 4. Standard UTF-8 decoding
    try:
        text = data.decode("utf-8")
        printable_count = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
        if printable_count / len(text) > 0.70:
            return text, "utf-8"
    except Exception:
        pass

    # 5. Latin-1 / CP1252 guaranteed lossless fallback
    try:
        return data.decode("latin-1"), "latin-1"
    except Exception:
        return None, "decode_failed"


def extract_raw_byte_array(elements: List[Any]) -> Optional[bytes]:
    """
    Extracts raw bytes from an AST node array or literal integer list.
    Supports @(31, 139, 8, ...) and [byte[]]@(...) representations.
    """
    out = bytearray()
    for el in elements:
        if isinstance(el, int):
            out.append(el & 0xFF)
        elif hasattr(el, "value") and isinstance(el.value, int):
            out.append(el.value & 0xFF)
        else:
            return None
    return bytes(out)
