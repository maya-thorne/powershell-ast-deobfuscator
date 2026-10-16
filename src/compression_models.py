"""
Data models and telemetry definitions for in-memory compressed stream deobfuscation.
Covers GzipStream, DeflateStream, BrotliStream, and related memory stream operations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class CompressionType(str, Enum):
    """Supported stream compression algorithm types."""
    GZIP = "gzip"
    DEFLATE = "deflate"
    BROTLI = "brotli"
    UNKNOWN = "unknown"


class StreamEncoding(str, Enum):
    """Supported payload character encodings."""
    UTF8 = "utf-8"
    UTF16LE = "utf-16le"
    UTF16BE = "utf-16be"
    ASCII = "ascii"
    LATIN1 = "latin-1"
    AUTO = "auto"


@dataclass
class DecompressedStreamLayer:
    """
    Forensic record of a single decompressed stream layer.
    Captures compression algorithm, entropy metrics, ratio, and decompressed payload.
    """
    depth: int
    compression_type: CompressionType
    compressed_size: int
    decompressed_size: int
    compression_ratio: float
    detected_encoding: str
    entropy_before: float
    entropy_after: float
    raw_expression: str
    decompressed_text: str


@dataclass
class StreamDecompressionResult:
    """
    Cumulative result returned by stream deobfuscation passes.
    """
    original_script: str
    unwrapped_script: str
    layers: List[DecompressedStreamLayer] = field(default_factory=list)
    total_layers: int = 0
    has_decompressed_streams: bool = False
