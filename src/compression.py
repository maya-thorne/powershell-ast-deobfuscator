"""
Unified public facade for in-memory stream decompression and deobfuscation.
Exposes stream reducers, raw byte decompressors, and layer telemetry models.
"""

from typing import Any, Dict, List, Optional, Tuple

from .compression_decompressor import (
    calculate_entropy,
    decode_stream_bytes,
    decompress_stream_bytes,
    extract_raw_byte_array,
    parse_base64_stream,
)
from .compression_models import (
    CompressionType,
    DecompressedStreamLayer,
    StreamDecompressionResult,
    StreamEncoding,
)
from .compression_reducer import PowerShellCompressionReducer


def decompress_stream_payload(
    payload: str,
    preferred_type: Optional[CompressionType] = None,
) -> Optional[Tuple[str, CompressionType]]:
    """
    Decodes and decompresses a Base64 encoded stream payload.
    Returns (decompressed_text, detected_compression_type) or None on failure.
    """
    raw_bytes = parse_base64_stream(payload)
    if not raw_bytes:
        return None

    decompressed_bytes, comp_type = decompress_stream_bytes(raw_bytes, preferred_type)
    if not decompressed_bytes:
        return None

    text, _ = decode_stream_bytes(decompressed_bytes)
    if not text:
        return None

    return text, comp_type


__all__ = [
    "CompressionType",
    "StreamEncoding",
    "DecompressedStreamLayer",
    "StreamDecompressionResult",
    "PowerShellCompressionReducer",
    "decompress_stream_bytes",
    "decode_stream_bytes",
    "decompress_stream_payload",
    "calculate_entropy",
    "parse_base64_stream",
    "extract_raw_byte_array",
]
