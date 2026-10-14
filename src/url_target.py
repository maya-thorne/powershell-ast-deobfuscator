"""
PowerShell Remote Payload URL Data Model, IP Decoders, and Protocol Target Constants.
Forensic data structures and ReDoS-safe normalization helpers for carved remote payload URLs.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit


@dataclass
class RemotePayloadTarget:
    """
    Forensic data model representing a carved remote payload download target.
    """
    url: str
    raw_url: str
    method: str
    api_type: str
    destination_file: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    cradle_type: str = "generic_download"
    scheme: str = ""
    host: str = ""
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    ip_decoded: Optional[str] = None
    is_valid_url: bool = True
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Serializes remote payload target to JSON-compatible dictionary."""
        return {
            "url": self.url,
            "raw_url": self.raw_url,
            "method": self.method,
            "api_type": self.api_type,
            "destination_file": self.destination_file,
            "headers": self.headers,
            "proxy": self.proxy,
            "cradle_type": self.cradle_type,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "ip_decoded": self.ip_decoded,
            "is_valid_url": self.is_valid_url,
            "confidence": self.confidence,
        }


def decode_ip_part(part: str) -> int:
    """
    Decodes an IP address octet string in decimal, hexadecimal, or octal representation.
    """
    p = part.strip()
    if p.lower().startswith("0x"):
        return int(p, 16)
    if p.startswith("0") and len(p) > 1 and all(c in "01234567" for c in p):
        return int(p, 8)
    return int(p, 10)


def decode_host_ip(host: str) -> Tuple[str, Optional[str]]:
    """
    Decodes decimal DWORD, hexadecimal, octal, or dotted IP representations.
    Returns (canonical_host, ip_decoded_note_if_obfuscated).
    """
    h = host.strip()
    if not h:
        return h, None

    # 1. Decimal DWORD or single 32-bit hex integer (e.g. 2130706433 or 0x7f000001)
    if re.match(r"^(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10})$", h):
        try:
            val = int(h, 16 if h.lower().startswith("0x") else 10)
            if 0 <= val <= 0xFFFFFFFF:
                b1 = (val >> 24) & 0xFF
                b2 = (val >> 16) & 0xFF
                b3 = (val >> 8) & 0xFF
                b4 = val & 0xFF
                decoded = f"{b1}.{b2}.{b3}.{b4}"
                return decoded, f"{h} -> {decoded}"
        except ValueError:
            pass

    # 2. 4-part dotted notation with hex or octal octets (e.g. 0177.0.0.1 or 0x7f.0.0.1)
    parts = h.split(".")
    if len(parts) == 4:
        try:
            nums = [decode_ip_part(p) for p in parts]
            if all(0 <= n <= 255 for n in nums):
                is_obf = any(
                    p.lower().startswith("0x")
                    or (p.startswith("0") and len(p) > 1 and p != "0")
                    for p in parts
                )
                decoded = ".".join(str(n) for n in nums)
                if is_obf:
                    return decoded, f"{h} -> {decoded}"
                return decoded, None
        except ValueError:
            pass

    return h, None


def canonicalize_url(
    raw_url: str
) -> Tuple[str, str, str, Optional[int], str, str, Optional[str], bool]:
    """
    Normalizes a URL string: strips whitespace/backticks, extracts components,
    and resolves obfuscated IP formats.
    Returns (canonical_url, scheme, host, port, path, query, ip_decoded_note, is_valid).
    """
    clean = raw_url.strip().replace("`", "")

    # Auto-prepend scheme if missing standard prefix
    has_explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", clean))
    probe_url = clean if has_explicit_scheme else f"http://{clean}"

    try:
        parsed = urlsplit(probe_url)
        scheme = parsed.scheme.lower() if has_explicit_scheme else "http"
        raw_host = parsed.hostname or ""
        port = parsed.port
        path = parsed.path
        query = parsed.query

        canonical_host, ip_decoded = decode_host_ip(raw_host)

        # Reconstruct canonical netloc
        netloc = canonical_host
        if port is not None:
            netloc = f"{canonical_host}:{port}"

        canonical_url = urlunsplit((scheme, netloc, path, query, parsed.fragment))
        is_valid = bool(canonical_host) and (
            has_explicit_scheme or "." in canonical_host or canonical_host == "localhost"
        )
        return (canonical_url, scheme, canonical_host, port, path, query, ip_decoded, is_valid)
    except Exception:
        return (clean, "", clean, None, "", "", None, False)


# Recognized download method identifiers
WEBCLIENT_DOWNLOAD_METHODS: Set[str] = {
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "openread",
    "openwrite",
    "uploadstring",
    "uploaddata",
    "uploadfile",
    "downloadstringasync",
    "downloadfileasync",
    "downloaddataasync",
}

HTTPCLIENT_DOWNLOAD_METHODS: Set[str] = {
    "getstringasync",
    "getbytearrayasync",
    "getstreamasync",
    "getasync",
    "sendasync",
}

DOWNLOAD_CMDLETS: Set[str] = {
    "invoke-webrequest",
    "iwr",
    "curl",
    "wget",
    "invoke-restmethod",
    "irm",
    "start-bitstransfer",
}
