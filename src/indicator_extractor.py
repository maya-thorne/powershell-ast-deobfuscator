"""
PowerShell Threat Indicator Extractor.
Analyzes raw and deobfuscated scripts and AST structures to extract high-fidelity
indicators of compromise (IoCs), network C2 targets, defense evasion hooks,
execution cradles, and memory injection patterns for rule synthesis.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .amsi_etw_detector import PowerShellAmsiEtwDetector
from .amsi_etw_signatures import AmsiEtwFinding
from .rule_models import IndicatorCategory, RuleSynthesisOptions, ThreatIndicator
from .webclient_tracer import RemotePayloadTarget, carve_all_urls, extract_download_urls


class PowerShellIndicatorExtractor:
    """
    Compiler-aware forensic indicator extractor for PowerShell malware scripts.
    Identifies high-relevance behavioral signatures across raw and AST-deobfuscated payloads.
    """

    # High-signal memory allocation and process injection Windows APIs
    MEMORY_INJECTION_APIS: Dict[str, Tuple[str, float]] = {
        "VirtualAlloc": ("Virtual memory allocation API", 9.0),
        "VirtualProtect": ("Memory protection modification API", 9.0),
        "CreateThread": ("Native thread execution API", 8.5),
        "CreateRemoteThread": ("Remote process thread injection API", 9.5),
        "WriteProcessMemory": ("Remote process memory write API", 9.5),
        "QueueUserAPC": ("Asynchronous Procedure Call injection API", 9.0),
        "RtlMoveMemory": ("Kernel memory copy API", 8.5),
        "GetProcAddress": ("Dynamic API export resolution", 7.5),
        "LoadLibrary": ("Dynamic DLL loading API", 7.5),
        "Marshal.Copy": ("Managed to unmanaged memory copy", 8.0),
        "Marshal.GetDelegateForFunctionPointer": ("Dynamic native function pointer invocation", 8.5),
    }

    # Execution vectors and download cradles
    EXECUTION_CRADLE_PATTERNS: Dict[str, Tuple[str, float]] = {
        "DownloadString": ("WebClient string download cradle", 8.5),
        "DownloadData": ("WebClient byte array download cradle", 8.5),
        "DownloadFile": ("WebClient file download cradle", 8.0),
        "OpenRead": ("WebClient stream download cradle", 8.0),
        "Invoke-Expression": ("Dynamic expression evaluation cmdlet", 7.5),
        "[ScriptBlock]::Create": ("ScriptBlock dynamic compilation", 8.0),
        "InvokeScript": ("ExecutionContext script evaluation", 8.0),
        "Invoke-WebRequest": ("HTTP request cmdlet", 6.5),
        "Invoke-RestMethod": ("REST endpoint query cmdlet", 6.5),
        "Start-Process": ("Process execution cmdlet", 6.0),
        "WScript.Shell": ("COM automation shell execution", 7.5),
        "Shell.Application": ("COM shell application dispatcher", 7.5),
    }

    # Persistence mechanisms
    PERSISTENCE_PATTERNS: Dict[str, Tuple[str, float]] = {
        r"CurrentVersion\\Run": ("Registry Run key autostart persistence", 8.5),
        r"CurrentVersion\\RunOnce": ("Registry RunOnce key autostart persistence", 8.5),
        "New-ScheduledTaskAction": ("Scheduled task creation cmdlet", 8.0),
        "Register-ScheduledTask": ("Scheduled task registration cmdlet", 8.0),
        "__EventFilter": ("WMI persistence event filter", 9.0),
        "CommandLineEventConsumer": ("WMI persistence command line consumer", 9.0),
        "__FilterToConsumerBinding": ("WMI persistence filter-consumer binding", 9.0),
    }

    # Cryptographic unboxing and compression
    CRYPTO_OBFUSCATION_PATTERNS: Dict[str, Tuple[str, float]] = {
        "FromBase64String": ("Base64 byte decoding method", 6.5),
        "IO.Compression.DeflateStream": ("In-memory Deflate decompression stream", 8.0),
        "IO.Compression.GZipStream": ("In-memory GZip decompression stream", 8.0),
        "Security.Cryptography.Aes": ("AES managed cryptographic cipher", 7.5),
        "RijndaelManaged": ("Rijndael cipher implementation", 7.5),
        "ConvertTo-SecureString": ("SecureString encryption cmdlet", 7.0),
    }

    # Suspicious .NET reflection and dynamic compilation APIs
    SUSPICIOUS_REFLECTION_APIS: Dict[str, Tuple[str, float]] = {
        "[System.Reflection.Assembly]::Load": ("In-memory .NET assembly loader", 9.0),
        "Add-Type": ("Inline C# / .NET code compilation cmdlet", 8.0),
        "GetMethod": ("Reflection member method lookup", 6.0),
        "GetField": ("Reflection private field lookup", 6.0),
        "NonPublic": ("Reflection non-public member access flag", 6.5),
    }

    # Known AMSI & ETW memory patch byte opcodes
    PATCH_BYTE_SIGNATURES: List[Tuple[str, str, float]] = [
        ("C3", "Ret opcode patch (AmsiScanBuffer/EtwEventWrite)", 9.5),
        ("C2 14 00", "Ret 0x14 callee stack cleanup patch (EtwEventWrite 32-bit)", 9.5),
        ("B8 57 00 07 80 C3", "E_INVALIDARG return value patch (AmsiScanBuffer 64-bit)", 10.0),
        ("31 C0 C3", "Xor eax, eax ; Ret (S_OK / AMSI_RESULT_CLEAN patch)", 10.0),
    ]

    # Stopwords to discard trivial noise
    STOPWORDS: Set[str] = {
        "if", "else", "elseif", "while", "for", "foreach", "in", "param", "return",
        "try", "catch", "finally", "switch", "default", "function", "filter",
        "write-host", "write-output", "out-null", "out-string", "select-object",
        "where-object", "get-member", "measure-object", "true", "false", "null",
        "this", "args", "input", "error", "item", "var", "temp", "data", "path",
        "powershell", "pwsh", "cmd", "exe", "system", "string", "int", "char",
        "byte", "array", "void", "object", "boolean", "new-object", "set-variable",
        "get-variable", "clear-variable", "remove-variable",
    }

    def __init__(self) -> None:
        self.amsi_detector = PowerShellAmsiEtwDetector()

    def extract_indicators(
        self,
        raw_script: str,
        deobfuscated_script: Optional[str] = None,
        options: Optional[RuleSynthesisOptions] = None,
    ) -> List[ThreatIndicator]:
        """
        Extracts, ranks, and deduplicates threat indicators from raw and deobfuscated scripts.
        """
        opts = options or RuleSynthesisOptions()
        indicators: List[ThreatIndicator] = []
        seen_values: Set[str] = set()

        deobf = deobfuscated_script if deobfuscated_script is not None else raw_script

        # 1. Carve network C2 targets (URLs, IPs, domains)
        self._extract_network_indicators(raw_script, deobf, indicators, seen_values)

        # 2. Extract AMSI and ETW bypass signatures
        self._extract_amsi_etw_indicators(raw_script, deobf, indicators, seen_values)

        # 3. Extract memory injection and process manipulation APIs
        self._extract_pattern_indicators(
            raw_script,
            deobf,
            self.MEMORY_INJECTION_APIS,
            IndicatorCategory.MEMORY_INJECTION,
            ["T1055"],
            indicators,
            seen_values,
        )

        # 4. Extract execution cradles and download methods
        self._extract_pattern_indicators(
            raw_script,
            deobf,
            self.EXECUTION_CRADLE_PATTERNS,
            IndicatorCategory.EXECUTION_CRADLE,
            ["T1059.001", "T1105"],
            indicators,
            seen_values,
        )

        # 5. Extract persistence mechanisms
        self._extract_pattern_indicators(
            raw_script,
            deobf,
            self.PERSISTENCE_PATTERNS,
            IndicatorCategory.PERSISTENCE,
            ["T1547.001"],
            indicators,
            seen_values,
        )

        # 6. Extract cryptographic and compression routines
        self._extract_pattern_indicators(
            raw_script,
            deobf,
            self.CRYPTO_OBFUSCATION_PATTERNS,
            IndicatorCategory.CRYPTO_OBFUSCATION,
            ["T1027"],
            indicators,
            seen_values,
        )

        # 7. Extract reflection and inline compilation APIs
        self._extract_pattern_indicators(
            raw_script,
            deobf,
            self.SUSPICIOUS_REFLECTION_APIS,
            IndicatorCategory.SUSPICIOUS_API,
            ["T1059.001"],
            indicators,
            seen_values,
        )

        # 8. Extract suspicious file drops and target identifiers
        self._extract_target_identifiers(raw_script, deobf, indicators, seen_values)

        # Filter by minimum weight threshold and scope
        filtered: List[ThreatIndicator] = []
        for ind in indicators:
            if ind.weight < opts.min_weight:
                continue
            if opts.target_scope == "raw" and ind.is_deobfuscated_only:
                continue
            filtered.append(ind)

        # Sort by weight descending, then value length descending
        filtered.sort(key=lambda x: (x.weight, len(x.value)), reverse=True)

        # Cap at max_strings limit if necessary
        return filtered[: opts.max_strings]

    def _extract_network_indicators(
        self,
        raw_script: str,
        deobf_script: str,
        indicators: List[ThreatIndicator],
        seen_values: Set[str],
    ) -> None:
        """Extracts carved remote payload targets, URLs, IPs, and hostnames."""
        # Carve from deobfuscated first, then raw
        targets_deobf = carve_all_urls(deobf_script)
        targets_raw = carve_all_urls(raw_script)

        for target in targets_deobf:
            val = target.url.strip()
            if not val or val.lower() in seen_values:
                continue
            seen_values.add(val.lower())
            is_deobf_only = val not in raw_script

            indicators.append(
                ThreatIndicator(
                    category=IndicatorCategory.NETWORK_C2,
                    value=val,
                    indicator_type="url",
                    weight=9.5,
                    description=f"Carved remote payload C2 URL via {target.method}",
                    mitre_techniques=["T1071.001", "T1105"],
                    raw_match=target.raw_url,
                    is_deobfuscated_only=is_deobf_only,
                    metadata={"host": target.host, "port": target.port, "method": target.method},
                )
            )

            # Also add host IP/domain if specific
            host = target.host.strip()
            if host and host.lower() not in seen_values and not host.startswith("127.0."):
                seen_values.add(host.lower())
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.NETWORK_C2,
                        value=host,
                        indicator_type="ip" if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else "domain",
                        weight=8.5,
                        description=f"Carved C2 host/domain ({host})",
                        mitre_techniques=["T1071.001"],
                        is_deobfuscated_only=host not in raw_script,
                    )
                )

        # Process any remaining targets in raw script not yet seen
        for target in targets_raw:
            val = target.url.strip()
            if not val or val.lower() in seen_values:
                continue
            seen_values.add(val.lower())
            indicators.append(
                ThreatIndicator(
                    category=IndicatorCategory.NETWORK_C2,
                    value=val,
                    indicator_type="url",
                    weight=9.5,
                    description=f"Carved remote payload C2 URL via {target.method}",
                    mitre_techniques=["T1071.001", "T1105"],
                    raw_match=target.raw_url,
                    is_deobfuscated_only=False,
                    metadata={"host": target.host, "port": target.port, "method": target.method},
                )
            )

    def _extract_amsi_etw_indicators(
        self,
        raw_script: str,
        deobf_script: str,
        indicators: List[ThreatIndicator],
        seen_values: Set[str],
    ) -> None:
        """Extracts AMSI and ETW bypass signatures, patch opcodes, and target symbols."""
        findings_deobf = self.amsi_detector.detect(deobf_script)
        findings_raw = self.amsi_detector.detect(raw_script)

        all_findings = findings_deobf + findings_raw
        for finding in all_findings:
            val = finding.target_symbol.strip()
            if not val or val.lower() in seen_values:
                continue
            seen_values.add(val.lower())

            weight = 9.0 if finding.severity.value == "critical" else 8.0
            is_deobf_only = val not in raw_script

            indicators.append(
                ThreatIndicator(
                    category=IndicatorCategory.DEFENSE_EVASION,
                    value=val,
                    indicator_type="api",
                    weight=weight,
                    description=f"{finding.signature_name} ({finding.category.value})",
                    mitre_techniques=["T1562.001"],
                    raw_match=finding.matched_text,
                    is_deobfuscated_only=is_deobf_only,
                    metadata={
                        "signature_id": finding.signature_id,
                        "target_system": finding.target_system.value,
                        "severity": finding.severity.value,
                    },
                )
            )

        # Check for known patch byte opcodes in deobfuscated or raw scripts
        combined_text = f"{raw_script}\n{deobf_script}"
        for hex_pattern, desc, weight in self.PATCH_BYTE_SIGNATURES:
            # Check if hex bytes appear (e.g., 0xC3, 0x57, or hex arrays)
            bytes_list = hex_pattern.split()
            formatted_hex = f"{{{hex_pattern}}}"
            if formatted_hex.lower() in seen_values:
                continue

            # Look for byte representations in script (e.g. 0xC3 or 0xc3 or 195)
            pattern_found = False
            if len(bytes_list) == 1:
                b = bytes_list[0]
                regex = rf"\b0x{b}\b"
                if re.search(regex, combined_text, re.IGNORECASE):
                    pattern_found = True
            else:
                # Multiple byte sequence
                hex_seq = r"[\s,]+".join([rf"0x{b}" for b in bytes_list])
                if re.search(hex_seq, combined_text, re.IGNORECASE):
                    pattern_found = True

            if pattern_found:
                seen_values.add(formatted_hex.lower())
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.DEFENSE_EVASION,
                        value=hex_pattern,
                        indicator_type="hex",
                        weight=weight,
                        description=desc,
                        mitre_techniques=["T1562.001"],
                        is_deobfuscated_only=hex_pattern not in raw_script,
                    )
                )

    def _extract_pattern_indicators(
        self,
        raw_script: str,
        deobf_script: str,
        pattern_dict: Dict[str, Tuple[str, float]],
        category: IndicatorCategory,
        mitre_ids: List[str],
        indicators: List[ThreatIndicator],
        seen_values: Set[str],
    ) -> None:
        """Generic pattern matcher across scripts for predefined dictionary catalogs."""
        for pattern_str, (description, weight) in pattern_dict.items():
            if pattern_str.lower() in seen_values:
                continue

            # Case-insensitive substring or regex search
            in_deobf = re.search(re.escape(pattern_str), deobf_script, re.IGNORECASE) is not None
            in_raw = re.search(re.escape(pattern_str), raw_script, re.IGNORECASE) is not None

            if in_deobf or in_raw:
                seen_values.add(pattern_str.lower())
                indicators.append(
                    ThreatIndicator(
                        category=category,
                        value=pattern_str,
                        indicator_type="text",
                        weight=weight,
                        description=description,
                        mitre_techniques=list(mitre_ids),
                        is_deobfuscated_only=in_deobf and not in_raw,
                    )
                )

    def _extract_target_identifiers(
        self,
        raw_script: str,
        deobf_script: str,
        indicators: List[ThreatIndicator],
        seen_values: Set[str],
    ) -> None:
        """Extracts suspicious file drop paths, executable names, and GUIDs."""
        combined_text = f"{deobf_script}\n{raw_script}"

        # 1. Suspicious file paths (.exe, .dll, .ps1, .bat, .vbs)
        file_matches = re.findall(
            r"""(?:['"]|\b)([a-zA-Z0-9_\-\\\/\.\:\$]+\.(?:exe|dll|ps1|bat|vbs|tmp))(?:['"]|\b)""",
            combined_text,
            re.IGNORECASE,
        )
        for filepath in file_matches:
            val = filepath.strip()
            if not val or len(val) < 4:
                continue

            # Add full path if not seen
            if val.lower() not in seen_values:
                seen_values.add(val.lower())
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.TARGET_IDENTIFIER,
                        value=val,
                        indicator_type="text",
                        weight=7.5,
                        description=f"Suspicious payload artifact file path ({val})",
                        mitre_techniques=["T1059.001"],
                        is_deobfuscated_only=val not in raw_script,
                    )
                )

            # Also add bare filename if different from full path
            basename = re.split(r"[\\\/]", val)[-1]
            if basename and basename.lower() != val.lower() and basename.lower() not in seen_values and len(basename) >= 4:
                seen_values.add(basename.lower())
                indicators.append(
                    ThreatIndicator(
                        category=IndicatorCategory.TARGET_IDENTIFIER,
                        value=basename,
                        indicator_type="text",
                        weight=7.5,
                        description=f"Suspicious payload artifact file name ({basename})",
                        mitre_techniques=["T1059.001"],
                        is_deobfuscated_only=basename not in raw_script,
                    )
                )

        # 2. Extract GUID patterns
        guid_matches = re.findall(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            combined_text,
        )
        for guid in guid_matches:
            val = guid.strip()
            if val.lower() in seen_values:
                continue
            seen_values.add(val.lower())
            indicators.append(
                ThreatIndicator(
                    category=IndicatorCategory.TARGET_IDENTIFIER,
                    value=val,
                    indicator_type="text",
                    weight=7.0,
                    description=f"Extracted CLSID/GUID identifier ({val})",
                    mitre_techniques=["T1059.001"],
                    is_deobfuscated_only=val not in raw_script,
                )
            )
