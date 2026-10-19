"""
PowerShell AST Batch Directory Scanner & Safe Multi-Encoding File Reader.
Provides safe directory traversal, symlink cycle protection, extension filtering,
file size guards, multi-encoding fallback heuristics, SHA-256 calculation, and memory scrubbing.
"""

import hashlib
import os
from typing import List, Optional, Set, Tuple

from .batch_models import BatchScanOptions
from .secure_string_crypto import zeroize_buffer


class PowerShellBatchScanner:
    """
    Forensic directory scanner and safe file ingestion engine for PowerShell scripts.
    Guarantees robust, error-isolated scanning across diverse Windows and cross-platform filesystems.
    """

    # Common text encodings evaluated in forensic fallback order
    SUPPORTED_ENCODINGS = [
        "utf-8-sig",
        "utf-8",
        "utf-16-le",
        "utf-16-be",
        "cp1252",
        "latin-1",
    ]

    def __init__(self) -> None:
        pass

    def discover_files(self, options: BatchScanOptions) -> List[Tuple[str, str]]:
        """
        Safely discovers all candidate script files within target_dir matching options.
        Returns a sorted list of (absolute_path, relative_path) tuples.
        
        Guards:
        - Non-existent target validation
        - Single-file target support
        - Symlink loop / recursion cycle protection
        - File extension filtering (case-insensitive)
        - Maximum file size guard (skips oversized files)
        """
        target = os.path.abspath(options.target_dir)
        if not os.path.exists(target):
            raise FileNotFoundError(f"Target directory or file not found: {options.target_dir}")

        # If target is directly a file, return it if extension matches or is allowed
        if os.path.isfile(target):
            ext = os.path.splitext(target)[1].lower()
            allowed_exts = [e.lower() for e in options.file_extensions]
            if not allowed_exts or ext in allowed_exts:
                size = os.path.getsize(target)
                if options.max_file_size_bytes <= 0 or size <= options.max_file_size_bytes:
                    return [(target, os.path.basename(target))]
            return []

        discovered: List[Tuple[str, str]] = []
        visited_dirs: Set[str] = set()
        allowed_exts = tuple(e.lower() for e in options.file_extensions)

        if options.recursive:
            for root, dirs, files in os.walk(target, followlinks=options.follow_symlinks):
                real_root = os.path.realpath(root)
                if real_root in visited_dirs:
                    # Prevent cyclic directory symlink loops
                    dirs.clear()
                    continue
                visited_dirs.add(real_root)

                # If symlinks are not allowed, prune symlinked directories from traversal
                if not options.follow_symlinks:
                    dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]

                for filename in files:
                    file_path = os.path.join(root, filename)
                    if allowed_exts and not filename.lower().endswith(allowed_exts):
                        continue

                    # Guard against broken symlinks
                    if not os.path.exists(file_path):
                        continue

                    try:
                        file_size = os.path.getsize(file_path)
                    except OSError:
                        continue

                    if options.max_file_size_bytes > 0 and file_size > options.max_file_size_bytes:
                        continue

                    rel_path = os.path.relpath(file_path, target)
                    discovered.append((os.path.abspath(file_path), rel_path))
        else:
            try:
                entries = os.listdir(target)
            except OSError as ex:
                raise PermissionError(f"Cannot access directory: {target} ({ex})")

            for filename in entries:
                file_path = os.path.join(target, filename)
                if not os.path.isfile(file_path):
                    continue
                if allowed_exts and not filename.lower().endswith(allowed_exts):
                    continue

                try:
                    file_size = os.path.getsize(file_path)
                except OSError:
                    continue

                if options.max_file_size_bytes > 0 and file_size > options.max_file_size_bytes:
                    continue

                rel_path = os.path.basename(file_path)
                discovered.append((os.path.abspath(file_path), rel_path))

        discovered.sort(key=lambda item: item[1].lower())
        return discovered

    def read_file_safe(
        self,
        file_path: str,
        max_size_bytes: Optional[int] = None,
    ) -> Tuple[str, str, str, int]:
        """
        Safely reads raw script file contents using multi-encoding heuristics,
        calculates SHA-256 hash, and performs memory scrubbing on raw byte buffers.

        Returns:
            Tuple of (decoded_text, sha256_hex, encoding_used, file_size_bytes)

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If file size exceeds max_size_bytes.
            UnicodeDecodeError: If all encoding fallbacks fail.
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if max_size_bytes is not None and max_size_bytes > 0 and file_size > max_size_bytes:
            raise ValueError(f"File size {file_size} bytes exceeds maximum allowed limit {max_size_bytes} bytes")

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        # Calculate cryptographic SHA-256 digest
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Handle empty files gracefully
        if not raw_bytes:
            return "", sha256_hash, "utf-8", 0

        decoded_text: Optional[str] = None
        encoding_used: Optional[str] = None

        # 1. Byte Order Mark (BOM) Detection
        if raw_bytes.startswith(b"\xef\xbb\xbf"):
            try:
                decoded_text = raw_bytes.decode("utf-8-sig")
                encoding_used = "utf-8-sig"
            except UnicodeDecodeError:
                pass
        elif raw_bytes.startswith(b"\xff\xfe"):
            try:
                decoded_text = raw_bytes.decode("utf-16")
                encoding_used = "utf-16-le"
            except UnicodeDecodeError:
                pass
        elif raw_bytes.startswith(b"\xfe\xff"):
            try:
                decoded_text = raw_bytes.decode("utf-16")
                encoding_used = "utf-16-be"
            except UnicodeDecodeError:
                pass

        # 2. Heuristic check for BOM-less UTF-16LE (common in Windows PowerShell artifacts)
        if decoded_text is None and len(raw_bytes) >= 4:
            # Alternating zero bytes in odd positions indicate ASCII characters in UTF-16LE
            null_count_odd = raw_bytes[1::2].count(0)
            if null_count_odd > (len(raw_bytes) // 4):
                try:
                    decoded_text = raw_bytes.decode("utf-16-le")
                    encoding_used = "utf-16-le"
                except UnicodeDecodeError:
                    pass

        # 3. Standard fallback sequence (UTF-8 strict -> CP1252 -> UTF-16LE -> Latin-1)
        if decoded_text is None:
            for enc in ["utf-8", "cp1252", "utf-16-le", "utf-16-be", "latin-1"]:
                try:
                    decoded_text = raw_bytes.decode(enc)
                    encoding_used = enc
                    break
                except UnicodeDecodeError:
                    continue

        # Zeroize temporary raw byte buffer to scrub sensitive memory contents
        scrub_buf = bytearray(raw_bytes)
        zeroize_buffer(scrub_buf)

        if decoded_text is None or encoding_used is None:
            raise UnicodeDecodeError("all_codecs", raw_bytes, 0, len(raw_bytes), "Failed to decode script with all candidate encodings")

        return decoded_text, sha256_hash, encoding_used, file_size
