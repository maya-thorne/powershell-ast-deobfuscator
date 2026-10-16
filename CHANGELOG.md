# Changelog

All notable changes to `powershell-ast-deobfuscator` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.0] - 2026-10-16

### Added
- In-memory compressed stream deobfuscation and static AST reduction engine:
  - Stream decompression data models and telemetry definitions (`src/compression_models.py`):
    - Multi-algorithm enumeration: `CompressionType` (`GZIP`, `DEFLATE`, `BROTLI`, `UNKNOWN`).
    - Character encoding classifications: `StreamEncoding` (`UTF8`, `UTF16LE`, `UTF16BE`, `ASCII`, `LATIN1`, `AUTO`).
    - Forensic layer telemetry: `DecompressedStreamLayer` recording depth, compression ratio, byte sizes, entropy shifts, and decompressed payloads.
    - Aggregated result carrier: `StreamDecompressionResult` tracking total unboxed stream layers and execution flags.
  - Core byte decompressor and encoding heuristics (`src/compression_decompressor.py`):
    - Raw RFC 1951 DEFLATE decompression via `zlib.decompress(data, -zlib.MAX_WBITS)` handling native .NET `DeflateStream` outputs without zlib headers or checksums.
    - Standard RFC 1952 GZIP stream decompression via `gzip.decompress()` and `zlib.decompress(data, zlib.MAX_WBITS | 16)`.
    - Zlib-wrapped RFC 1950 DEFLATE stream decompression via `zlib.decompress(data, zlib.MAX_WBITS)`.
    - Optional RFC 7932 Brotli stream decompression with graceful fallback when `brotli` runtime extensions are absent.
    - Multi-encoding heuristics detecting UTF-8 / UTF-16LE / UTF-16BE byte order marks (BOMs), wide-character null byte alternation patterns, and lossless Latin-1 fallback.
    - Memory scrubbing (`zeroize_buffer`) wiping sensitive raw and decompressed byte buffers.
  - AST stream reducer and pattern unwrapper (`src/compression_reducer.py`):
    - Unboxing of nested one-liner constructors: `(New-Object IO.StreamReader(New-Object IO.Compression.GZipStream(New-Object IO.MemoryStream(,[Convert]::FromBase64String('...')), ...))).ReadToEnd()` -> `StringLiteralNode`.
    - Unboxing of .NET static constructor syntax: `[IO.StreamReader]::new([IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('...')))).ReadToEnd()`.
    - Multi-step variable tracking propagating streams across `$data`, `$bytes`, `$ms`, `$gz`, `$sr`, and `$script` assignment chains.
    - MemoryStream copying (`$gz.CopyTo($out)`) and byte array extraction (`$out.ToArray()`, `[System.Text.Encoding]::UTF8.GetString(...)`).
    - Pure-Python regex and pattern fallback scanner (`unwrap_text()`) for unparsed or fragmented scripts.
  - Unified public facade (`src/compression.py`):
    - Exposes `PowerShellCompressionReducer`, `decompress_stream_bytes`, `decode_stream_bytes`, `decompress_stream_payload`, and telemetry models.
  - Parser support for PowerShell unary comma operator (`src/parser.py`):
    - Enhanced `parse_unary_expression()` to cleanly parse unary comma array creation (`,$bytes`, `(,[Convert]...)`) into `ArrayLiteralNode`.
  - Multi-pass fixed-point engine integration (`src/deobfuscator_engine.py`, `src/normalizer.py`):
    - Integrated stream decompression pass into `PowerShellDeobfuscator` loop and `PowerShellNormalizer`.
    - Exposed `last_compression_layers` telemetry on `PowerShellDeobfuscator`.
- CLI stream forensics flags (`src/cli.py`):
  - Added `--decompress-streams` (default True) and `--no-decompress-streams`.
  - Added `--trace-streams`: outputs detailed forensic JSON telemetry of all detected and decompressed stream layers.
- Comprehensive unit and integration test coverage (`tests/test_compression_decompressor.py`):
  - 22 new tests verifying raw byte decompression, multi-encoding detection, one-liner and multi-step AST reduction, CopyTo extraction, IEX unwrapping integration, fixed-point convergence, buffer zeroization, and CLI flags (expanding test suite to 418 tests, 100% pass).

## [0.15.0] - 2026-10-16

### Added
- Automated YARA 4.x and SigmaHQ threat hunting rule synthesis engine:
  - Threat indicator taxonomy and data models (`src/rule_models.py`):
    - Multi-category indicator classification: `IndicatorCategory` (NETWORK_C2, DEFENSE_EVASION, EXECUTION_CRADLE, MEMORY_INJECTION, PERSISTENCE, CRYPTO_OBFUSCATION, SUSPICIOUS_API, TARGET_IDENTIFIER).
    - Curated MITRE ATT&CK Enterprise Matrix catalog mapping techniques (T1059.001, T1562.001, T1027, T1105, T1055, T1071.001, T1547.001, T1053.005, T1546.004, T1082) to Sigma standard tags.
    - Deterministic UUIDv5 rule identifiers and standardized metadata structures (`RuleMetadata`, `RuleSynthesisOptions`).
  - High-fidelity forensic indicator extractor (`src/indicator_extractor.py`):
    - AST-aware indicator extraction correlating carved download URLs, remote hosts, AMSI/ETW bypass hooks, memory allocation APIs (VirtualAlloc, VirtualProtect, CreateRemoteThread), execution cradles (DownloadString, [ScriptBlock]::Create), persistence keys, and cryptographic streams.
    - Scope tracking: identifies indicators concealed by obfuscation layers (`is_deobfuscated_only`) vs. raw artifact strings.
    - Heuristic weighting (1.0 to 10.0 scale) and noise suppression against ubiquitous PowerShell keywords.
  - Compiler-grade YARA 4.x rule synthesizer (`src/yara_generator.py`):
    - Category-prefixed string identifiers (`$c2_*`, `$evas_*`, `$cradle_*`, `$mem_*`, `$persist_*`, `$api_*`, `$target_*`).
    - Standard modifiers (`ascii wide nocase`) and hex bytecode patterns (`{ C3 }`, `{ B8 57 00 07 80 C3 }`).
    - Robust condition synthesis supporting balanced correlation (`any of ($c2*) or (1 of ($evas*) and 1 of ($cradle*))`), strict, loose, and categorized multi-vector requirements with optional filesize gates.
    - Dual-scope mode with `$raw_*` and `$deobf_*` string prefixes.
    - Static YARA syntax verification and linting helper.
  - Standard-compliant SigmaHQ YAML rule generator (`src/sigma_generator.py`):
    - Multi-logsource support: PowerShell ScriptBlock Logging (Event ID 4104), Process Creation (Event ID 4688 / Sysmon 1), and Module Logging (Event ID 4103).
    - Pure-Python zero-dependency YAML serializer guaranteeing deterministic 2-space indentation and proper scalar quoting.
    - Category-grouped selection trees (`selection_c2`, `selection_evasion`, `selection_cradle`, `selection_injection`) with correlation condition trees.
  - Unified threat hunting facade and engine integration (`src/threat_rule_generator.py`, `src/deobfuscator_engine.py`):
    - Direct methods on `PowerShellDeobfuscator`: `generate_yara_rule()`, `generate_sigma_rule()`, and `generate_threat_rules()`.
    - Standalone rule generator facade with file export capabilities (`save_rules`).
- CLI threat hunting flags (`src/cli.py`):
  - Added `--generate-yara`: outputs synthesized YARA 4.x detection rule to stdout or file.
  - Added `--generate-sigma`: outputs synthesized Sigma YAML detection rule.
  - Added `--generate-rules`: outputs full ruleset bundle with indicator telemetry JSON.
  - Added `--rule-name` and `--rule-title`: customizable rule identifiers.
  - Added `--rule-target`: configurable scope selection (`deobfuscated`, `raw`, `dual`).
  - Added `--sigma-logsource`: target logsource selection (`scriptblock`, `process_creation`, `module`).
  - Added `--yara-condition`: condition style selection (`balanced`, `strict`, `loose`, `categorized`).
  - Added `--rule-output-dir`: destination directory to persist `.yar` and `.yml` files.
- Comprehensive test coverage (`tests/test_threat_rule_generator.py`):
  - 27 unit and integration tests covering indicator extraction, YARA syntax, string escaping, hex patterns, condition modes, Sigma YAML formatting, process creation, deobfuscator engine methods, rule persistence, and CLI execution (total test suite expanded to 396 tests, 100% pass).

## [0.14.0] - 2026-10-15

### Added
- AMSI & ETW bypass signature detection and ruleset engine (`src/amsi_etw_signatures.py`):
  - Structured categorization hierarchy: `BypassCategory` (MEMORY_PATCH, REFLECTION_TAMPERING, COM_HIJACK, CONTEXT_CORRUPTION, LOGGING_SUPPRESSION), `TargetSystem` (AMSI, ETW, WLDP, SCRIPT_LOGGING), and `BypassSeverity` (CRITICAL, HIGH, MEDIUM, LOW).
  - Curated 10-rule detection catalog (`BUILTIN_SIGNATURES`, `DEFAULT_RULESET`) with MITRE ATT&CK mapping (`T1562.001 - Impair Defenses: Disable or Modify Tools`).
  - Forensics telemetry models: `BypassSignature` and `AmsiEtwFinding` tracking signature ID, category, severity, target symbol, confidence score, and line numbers.
- Compiler-grade bypass detector and neutralization engine (`src/amsi_etw_detector.py`):
  - Memory patch detection: `AmsiScanBuffer` and `AmsiScanString` memory patches (VirtualProtect, Marshal.Copy, WriteProcessMemory, byte patterns 0xC3, 0xB8 0x57 0x00 0x07 0x80 0xC3, 0x31 0xC0 0xC3), `EtwEventWrite` memory patches (0xC3, 0xC2 0x14 0x00), `AmsiInitialize`/`AmsiOpenSession`, and `WLDP` dynamic code trust patches.
  - Reflection tampering detection: `amsiInitFailed` forced to true, `PSEtwLogProvider.etwProvider` nullification, `EventProvider.m_enabled` disabled to 0, and `cachedGroupPolicySettings` dictionary tampering (ScriptBlockLogging silencing).
  - Surgical sanitization and neutralization: supports comment wrapping (`mode="comment"`, `<# [NEUTRALIZED: ...] ... #>`), statement stripping (`mode="strip"`), and safe boolean inversion (`mode="invert"`) while preserving surrounding benign scripts.
  - Convenience public facades: `detect_amsi_etw()` and `neutralize_amsi_etw()`.
- Pipeline & CLI enhancements (`src/deobfuscator_engine.py`, `src/cli.py`):
  - Added `detect_amsi_etw`, `neutralize_amsi_etw`, and `neutralize_amsi_mode` parameters to `PowerShellDeobfuscator`, exposing `last_amsi_etw_findings`.
  - Added CLI flag `--detect-amsi`: exports structured JSON forensic findings across raw and deobfuscated payload variants.
  - Added CLI flag `--neutralize-amsi`: enables in-place neutralization of detected bypass blocks during deobfuscation.
  - Added CLI flag `--neutralize-mode`: configurable sanitization modes (`comment`, `strip`, `invert`).
  - Added CLI flag `--amsi-signatures`: dumps all registered detection signatures in JSON format.
- Unit and integration tests (`tests/test_amsi_etw_detector.py`):
  - 52 comprehensive tests verifying signature queries, memory patch detection, reflection tampering detection, neutralization modes (comment, strip, invert), benign code and scriptblock preservation, braced variables and hashtable boundary integrity, if-else compound control flow handling, multiple write statement claiming, logging suppression dictionaries, idempotent neutralization, constant-folded AST detection, deobfuscator engine integration, adversarial chained bypasses, AST call chain traversal, and CLI execution (total 369 tests passing with 100% success rate).


## [0.13.0] - 2026-10-15

### Added
- Recursive IEX (Invoke-Expression) wrapper tracking and peeling engine (`src/iex_unwrapper.py`):
  - Multi-vector invocation detection: direct cmdlet calls (`iex`, `Invoke-Expression`), call operator (`&`) and dot sourcing (`.`) with string/expression targets, ScriptBlock API invocations (`[scriptblock]::Create($code).Invoke()`, `.InvokeReturnAsIs()`), and ExecutionContext commands (`$ExecutionContext.InvokeCommand.InvokeScript($code)`).
  - Multi-stage pipeline streaming unwrapping (`'code' | iex | iex`) integrated with `src/pipeline_optimizer.py`.
  - Multi-statement ScriptBlock flattening with statement delimiter separation.
  - Dynamic download cradle retention: retains single network download cradles (`iex (New-Object Net.WebClient).DownloadString(...)`) while peeling redundant nested execution wrappers (`iex (iex (...))`).
  - Cryptographic cycle and loop guard: tracks SHA-256 hashes of intermediate payloads (`seen_hashes`) with hard nesting depth limit (`MAX_DEPTH = 30`).
  - Forensic layer telemetry model: `IEXLayer` and `IEXUnwrapResult` tracking step index, invocation vector, method name, unwrapped payload code, and SHA-256 hash.
  - Public facade utility functions: `unwrap_iex()`, `trace_iex_layers()`, and `peel_iex_string()`.
- CLI enhancements (`src/cli.py`):
  - Added `--trace-iex`: exports detailed JSON execution layer telemetry with invocation vectors, step indices, and hashes.
  - Added `--no-unwrap-iex`: allows disabling IEX peeling pass for raw forensic execution graph inspection.
- Integrated multi-pass normalization passes (`src/normalizer.py`, `src/deobfuscator_engine.py`):
  - Pass 11: IEX wrapper detection and peeling.
  - Pass 12: Cascading normalization over peeled script blocks and nested statements.
- Unit and integration tests (`tests/test_iex_unwrapper.py`):
  - 27 new tests covering direct invocations, call operators, ScriptBlock APIs, multi-stage pipelines, cycle detection, download cradle retention, format strings, XOR loops, and telemetry serialization (total 317 tests passing with 100% success rate).

### Changed
- CLI encoded command unwrapper regex hardened (`src/encoded_command_unwrapper.py`): balanced quote groups prevent stripping opening quotes when powershell CLI strings are enclosed in string arguments.
- Benchmark sample indicators updated (`src/benchmark_corpus.py`): ground-truth recall indicators updated to reflect peeled inner commands for peeled samples.

## [0.12.0] - 2026-10-14

### Added
- Compiler-grade arithmetic and bitwise static constant folding engine (`src/bitwise_folding_engine.py`):
  - Constant evaluation for binary bitwise operators: `-bxor`, `-band`, `-bor`, `-shl`, and `-shr`.
  - Constant evaluation for binary arithmetic operators: `+`, `-`, `*`, `/`, and `%` (with division-by-zero protection).
  - Constant evaluation for unary operators: `-bnot`, `-not`, `!`, arithmetic negation (`-`), unary plus (`+`), and `-join`.
  - Constant evaluation for comparison operators: `-eq`, `-ne`, `-gt`, `-ge`, `-lt`, and `-le`.
  - Immediate type-cast reduction over folded numeric expressions: `[char](0x41 -bxor 0x20)` -> `'a'`.
  - Shift bounds protection (clamped to 0..64) preventing denial-of-service and bit-shift overflow.
- Compiler-grade static XOR loop decryption and byte transform evaluator (`src/xor_loop_decryptor.py`):
  - Pipeline XOR loop resolution: `@(0x35, 0x21) | % { [char]($_ -bxor 0x55) }` -> `'ps'`.
  - Repeating multi-byte key cipher resolution: `$bytes | % { $_ -bxor $k[$i++ % $k.Length] }`.
  - Text encoding wrappers: `[System.Text.Encoding]::ASCII.GetString(...)` and `[System.Text.Encoding]::UTF8.GetString(...)`.
  - Imperative `for` loops with accumulator pattern: `for ($i=0; $i -lt $enc.Length; $i++) { $out += [char]($enc[$i] -bxor $key) }`.
  - Imperative `for` loops with in-place mutation: `for ($i=0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor $key }`.
  - Imperative `foreach` and `while` loop static unwrapping.
  - Cryptographic safety: enforces `zeroize_buffer()` memory scrubbing on decrypted plaintext buffers and key materials.
  - DoS mitigation: `MAX_LOOP_ITERATIONS = 50000` hard gate preventing infinite execution loops.
- Expanded AST Node hierarchy and Parser grammar (`src/ast_nodes.py`, `src/tokens.py`, `src/lexer.py`, `src/parser.py`):
  - Added `ForStatementNode` and `ForEachStatementNode`.
  - Added operator precedence tiers for bitwise (`-bxor`, `-band`, `-bor`) and bit shift (`-shl`, `-shr`) expressions.
  - Added lexer and parser support for postfix increment/decrement (`++`, `--`) and compound assignments (`+=`, `-=`).
  - Generalized method argument parsing to accept pipeline expressions directly (`[Encoding]::ASCII.GetString($data | % { ... })`).
- Visualizer and exporter extensions (`src/ast_visualizer.py`, `src/ast_exporter.py`):
  - Hierarchical tree, Mermaid flowchart, and Graphviz DOT support for `ForStatementNode` and `ForEachStatementNode`.
- Comprehensive test suites (`tests/test_bitwise_folding.py`, `tests/test_xor_loop_decryptor.py`):
  - 31 new unit and integration tests expanding total test count to 290 tests with 100% pass rate.

## [0.11.0] - 2026-10-14

### Added
- DownloadString and WebClient API static tracer and remote payload URL carving engine (`src/webclient_tracer.py`).
- Compiler-grade AST inspection extracting download method invocations across `System.Net.WebClient` (`DownloadString`, `DownloadFile`, `DownloadData`, `OpenRead`, `OpenWrite`, `UploadString`, `UploadData`, `UploadFile`, and async variants), `System.Net.Http.HttpClient` (`GetStringAsync`, `GetByteArrayAsync`, `GetStreamAsync`, `GetAsync`, `SendAsync`), and `System.Net.WebRequest` (`Create`).
- Download cmdlet and BSTR transfer static resolution supporting `Invoke-WebRequest` (`iwr`), `Invoke-RestMethod` (`irm`), and `Start-BitsTransfer` with automatic argument mapping for `-Uri`, `-OutFile`, `-UserAgent`, and `-Headers`.
- Obfuscated IP address auto-decoding:
  - Decimal DWORD integer IP resolution (e.g. `http://2130706433/` -> `http://127.0.0.1/`).
  - Single 32-bit hexadecimal integer IP resolution (e.g. `http://0x7f000001/` -> `http://127.0.0.1/`).
  - Dotted hexadecimal notation resolution (e.g. `http://0xC0.0xA8.0x01.0x01/` -> `http://192.168.1.1/`).
  - Dotted octal notation resolution (e.g. `http://0177.0.0.1/` -> `http://127.0.0.1/`).
- Forensic download cradle categorization identifying execution vectors: `iex_download_string`, `file_download_execute`, `in_memory_assembly_load`, `cmdlet_download`, `bits_transfer`, and `raw_string_carve`.
- Contextual state tracking associating WebClient headers (`$wc.Headers.Add(...)`, `$wc.Headers[...] = ...`) and proxy configurations (`$wc.Proxy = ...`) with downstream download operations.
- Heuristic fallback URL carver performing ReDoS-safe linear regex scanning over unstructured text, comments, and array literals.
- Structured `RemotePayloadTarget` forensic telemetry model with JSON serialization.
- Public utility facade functions: `trace_webclient()`, `carve_all_urls()`, and `extract_download_urls()`.
- CLI enhancements (`src/cli.py`):
  - `--carve-urls`: Dumps all carved remote download targets with full metadata as structured JSON.
  - `--urls`: Dumps deduplicated list of canonical remote payload URLs (one per line).
- Expanded parser grammar: generalized assignment statement parsing to handle property access (`$wc.Proxy = ...`) and array indexing (`$wc.Headers['User-Agent'] = ...`) as first-class l-values.
- Comprehensive unit and integration test suite (`tests/test_webclient_tracer.py`) with 22 new tests, expanding test coverage to 259 tests passing with 100% success rate.

## [0.10.0] - 2026-10-14

### Added
- Automated 30-sample obfuscated PowerShell benchmark corpus (`src/benchmark_corpus.py`) covering 10 distinct real-world evasion categories: String Concat & Backticks, Format Operator Shuffle, Type Casting & Array Join, Index Shuffling & Reverse Slicing, Special Environment & Preference Slicing, Reflection & Dynamic Member Invocation, Pipeline & ScriptBlock Control Flow, Recursive Base64 Encoded Commands, Subexpressions & Casing Randomization, and Cryptographic Envelopes & Composite APT Cradles.
- Standardized `CorpusSample` data structure modeling sample identity, category, attack context, expected ground-truth indicators, and MITRE ATT&CK technique tags.
- Corpus discovery and query helpers: `get_corpus()`, `get_sample(sample_id)`, and `get_corpus_by_category(category)`.
- Multi-dimensional benchmark metrics and fidelity measurement engine (`src/benchmark_metrics.py`):
  - Shannon entropy calculator (`calculate_entropy()`) measuring information density in bits per character.
  - Script size reduction delta calculator (`calculate_size_reduction()`).
  - Obfuscation artifact frequency detector (`detect_artifacts()`) identifying backticks, format operators, Base64 flags, shuffled index slices, nested subexpressions, and casing anomalies.
  - Ground-truth indicator recovery recall calculator (`calculate_indicator_recall()`) tracking recovered vs missing tokens.
  - Full AST syntax validity checker (`check_ast_validity()`) verifying parsed syntax tree integrity via `PowerShellLexer` and `PowerShellParser`.
  - Composite fidelity scoring model (`calculate_fidelity_score()`, 0.0 to 100.0%) weighting indicator recall (45%), AST validity (25%), artifact elimination (20%), and entropy stability (10%).
  - Telemetry dataclasses `SampleBenchmarkResult` and `CorpusBenchmarkSummary`.
- Automated benchmark runner and report generation engine (`src/benchmark_runner.py`):
  - Execution runners `run_sample()` and `run_benchmark()` measuring wall-clock latency per sample and across entire corpora.
  - Multi-format report serializers: ASCII text console table (`to_text_report()`), structured JSON (`to_json_report()`), and GitHub-Flavored Markdown (`to_markdown_report()`).
  - Safe UTF-8 file persistence helper (`save_report()`).
- Unified public facade (`src/benchmark.py`) exposing all benchmark corpus, metrics, and runner symbols.
- CLI enhancements (`src/cli.py`):
  - Added `--benchmark` flag to execute full corpus evaluation.
  - Added `--benchmark-sample <id>` to evaluate an isolated sample.
  - Added `--benchmark-category <category>` to evaluate category-specific sample subsets.
  - Added `--benchmark-report <path>` to persist reports directly to disk.
  - Added `--benchmark-format {text,json,markdown}` (default: text).
  - Made the positional `input` parameter optional (`nargs="?", default=None`) for clean benchmark execution without dummy strings.
- Comprehensive unit and integration test suite (`tests/test_benchmark_harness.py`) with 27 new tests, expanding test coverage to 237 tests passing with 100% success rate.

## [0.9.0] - 2026-10-13

### Added
- Subexpression unwrapping and flattening subsystem (`src/subexpression_unwrapper.py`) statically reducing obfuscated PowerShell subexpression splits (`$(...)`) and fragmented tokens to canonical AST nodes.
- Lexical and syntactic support for subexpressions: added `TokenType.DOLLAR_LPAREN` (`$(`) token and `SubexpressionNode(statements)` AST primitive supporting multi-statement execution, trailing semicolons, comma-separated array literals, member access chaining, and indexing.
- Redundant nested wrapper unboxing stripping arbitrary levels of redundant wrappers (`$((('calc.exe')))` -> `'calc.exe'`) and parenthesized expressions (`$((1 + 2))` -> `3`).
- In-subexpression concatenation and binary operation folding reducing string concatenation expressions (`$('i') + $('e') + $('x')` -> `'iex'`).
- Expandable double-quoted string interpolation reduction resolving nested subexpressions inside strings (`"prefix $( 'cmd' ) suffix"` -> `"prefix cmd suffix"`).
- Local variable assignment propagation within multi-statement subexpressions (`$($x = 'calc.exe'; $x)` -> `'calc.exe'`).
- Subexpression indexing reduction evaluating direct index accesses (`$('hello')[1]` -> `'e'`).
- PowerShell casing randomization normalizer (`src/casing_normalizer.py`) neutralizing mixed-case evasion techniques (`iNvOkE-eXpReSsIoN` -> `Invoke-Expression`).
- Comprehensive cmdlet dictionary covering 150+ cmdlets, aliases (`iex`, `gci`, `cat`, `curl`, `wget`, `rhu`), and 46 approved PowerShell verbs (`Get`, `Set`, `New`, `Invoke`, `Start`, `Stop`, `ConvertTo`, `ConvertFrom`, `Export`, `Import`, etc.) with PascalCase reconstruction for recognized cmdlets and Verb-Noun compounds.
- Canonical lowercasing for PowerShell language keywords (`if`, `else`, `elseif`, `while`, `for`, `foreach`, `switch`, `try`, `catch`, `finally`, `param`, `return`, `throw`, `trap`, `function`).
- .NET type accelerator and namespace canonicalization (`[ByTe[]]` -> `[byte[]]`, `[sYsTeM.nEt.wEbClIeNt]` -> `[System.Net.WebClient]`).
- Instance and static member method name canonicalization (`.SuBsTrInG()` -> `.Substring()`, `::fRoMbAsE64sTrInG()` -> `::FromBase64String()`).
- CLI parameter and flag canonicalization (`-eNcOdEdCoMmAnD` -> `-EncodedCommand`).
- Automatic and environment variable canonicalization (`$tRrUe` -> `$true`, `$FaLsE` -> `$false`, `$NuLl` -> `$null`, `$eNv:cOmSpEc` -> `$env:COMSPEC`).
- Dynamic member and method access unwrapping (`$obj.('sUbStRiNg')()` -> `$obj.Substring()`).
- Deobfuscator engine and CLI integration with `--normalize-casing` / `--no-normalize-casing` and `--unwrap-subexpr` / `--no-unwrap-subexpr` flags.
- Comprehensive test suites (`tests/test_subexpression_unwrapper.py` and `tests/test_casing_normalizer.py`) expanding total test coverage to 210 unit tests passing with 100% success rate.

## [0.8.0] - 2026-10-13

### Added
- Recursive Base64 encoded command unwrapping subsystem (`src/encoded_command_unwrapper.py`) statically extracting and decoding nested `-EncodedCommand`, `-enc`, and `-e` parameters across command strings and AST `CommandNode` structures.
- Support for all PowerShell parameter aliases and abbreviations (`-e`, `-en`, `-enc`, `-enco`, `-encod`, `-encode`, `-encoded`, `-encodedc`, `-encodedco`, `-encodedcom`, `-encodedcomm`, `-encodedcomma`, `-encodedcomman`, `-encodedcommand`, `/e`, `/enc`, `/encodedcommand`) with case-insensitivity and backtick evasion stripping (`-e`nc`, `-E`N`cOdEdCoMmAnD`).
- Parser and regex extraction for preceding launcher binaries (`powershell.exe`, `pwsh.exe`, `cmd /c powershell`, `& powershell`, `Start-Process`) and accompanying CLI flags (`-NoProfile`, `-NonInteractive`, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass`, `-Sta`, `-Version 2.0`).
- Multi-encoding auto-detection with BOM validation: evaluates UTF-16LE (PowerShell standard), UTF-8, UTF-16BE, ASCII, and Latin-1 based on byte frequency heuristics and null-byte distributions.
- Robust payload normalization repairing missing Base64 padding (`=` and `==`), stripping internal whitespace, tabs, and newlines, removing backtick escapes, handling URL-safe Base64 variants (`-` and `_`), and evaluating parenthesized string concatenations (`('part1' + 'part2')`).
- Multi-layer recursive unwrapping with cyclic loop protection using SHA-256 hash tracking and configurable recursion depth bounds (`max_depth = 50`).
- Layered forensic telemetry tracking layer depth, raw command, detected encoding, CLI binary, extracted flags, and Shannon entropy metrics before and after deobfuscation (`EncodedCommandLayer`, `UnwrapResult`).
- AST-level transformation inlining decoded script blocks directly into syntax trees for cascading multi-pass normalization.
- Command-line interface enhancements (`src/cli.py`) adding `--layers` (structured JSON telemetry dump) and `--extract-b64` (direct payload extraction).
- Comprehensive unit and integration test suite (`tests/test_encoded_command_unwrapper.py`) expanding total repository test suite to 173 tests passing with 100% success.

## [0.7.0] - 2026-10-13

### Added
- Hierarchical AST visualizer (`src/ast_visualizer.py`) rendering PowerShell abstract syntax trees in Unicode (`├──`, `└──`, `│`) and plain ASCII (`|--`, `\--`) formats with edge labels, child indexing, and depth guards.
- Multi-format AST exporter (`src/ast_exporter.py`) generating Mermaid flowchart diagrams (`flowchart TD`), Graphviz DOT graphs, structured JSON trees, and structural complexity metrics.
- Semantic Mermaid shape modeling mapping control flow (`IfStatementNode`, `WhileStatementNode`) to decision diamonds, scriptblocks to subroutines, literals/variables to stadiums, operators to rounded nodes, and types/members to trapezoids.
- Robust Mermaid and Graphviz character escaping sanitizing quotes, angle brackets, brackets, braces, and control characters to prevent syntax rendering errors.
- Structural AST complexity metrics extraction providing total node counts, maximum tree depth, per-type frequency distributions, statement/pipeline/command counts, and cyclomatic complexity scoring.
- Command-line interface enhancements (`src/cli.py`) adding `--ast`, `--tree`, `--mermaid`, `--dot`, `--json`, `--ascii`, `--format {tree,ascii,mermaid,json,dot,raw}`, and `--stats` flags with file output redirection (`-o`).
- Comprehensive unit and integration test suites (`tests/test_ast_visualizer.py` and `tests/test_ast_exporter.py`) expanding total test coverage to 149 tests with 100% pass rate.

## [0.6.0] - 2026-10-13

### Added
- Pipeline optimization engine (`src/pipeline_optimizer.py`) evaluating static pipelines, Foreach-Object (`%` / `foreach`), Select-Object (`select`), Where-Object (`?` / `where`), and Out-String.
- Foreach-Object mapping block static evaluation supporting character conversions (`(105, 101, 120 | % { [char]$_ }) -join ''` -> `'iex'`), bitwise XOR loops (`$_ -bxor 0x33`), arithmetic offsets (`$_ + 5`), string method invocations (`Trim`, `ToUpper`, `Substring`, `Replace`), format strings (`"{0:X2}" -f $_`), and property mappings (`% Length`).
- Select-Object slice and filter evaluation supporting `-First N`, `-Last N`, `-Skip N`, `-Index N`, `-Unique` deduplication, and `-ExpandProperty Length`.
- Where-Object static predicate evaluation supporting comparison operators (`-eq`, `-ne`, `-gt`, `-ge`, `-lt`, `-le`), wildcard pattern matching (`-like`, `-notlike`), and truthiness filtering.
- ScriptBlock and control flow simplification engine (`src/scriptblock_simplifier.py`) inlining call operators (`& { ... }`, `. { ... }`), method invocations (`{ ... }.Invoke()`), and indirect variable tracking (`$sb = { ... }; &$sb`).
- Conditional branch static folding for `IfStatementNode` (`if ($true)`, `if ($false)`) eliminating unreachable decoy branches and evaluating numeric, string, negation (`-not`, `!`), and comparison truthiness.
- Dead loop elimination for `WhileStatementNode` (`while ($false)`).
- AST hierarchy extensions: `IfStatementNode` and `WhileStatementNode` added to `src/ast_nodes.py`, `src/parser.py`, and `src/normalizer.py`.
- Parser support for bare comma arrays before pipelines (`105, 101, 120 | % ...`), PowerShell binary operators (`-bxor`, `-band`, `-bor`, `-shl`, `-shr`, `-eq`, `-ne`, `-gt`, `-ge`, `-lt`, `-le`, `-like`, `-notlike`), and unary negation (`-not`, `!`).
- Piped command simplification reducing `'calc.exe' | iex` to canonical `iex 'calc.exe'`.
- Dedicated unit and integration test suites (`tests/test_pipeline_optimizer.py` and `tests/test_scriptblock_simplifier.py`) expanding total test suite to 126 tests with 100% pass rate.

## [0.5.0] - 2026-10-13

### Added
- Reflection and dynamic member unwrapping engine (`src/reflection_unwrapper.py`) statically reducing obfuscated .NET reflection patterns to canonical PowerShell syntax.
- Static reflection method invocation unwrapping for `[Type].GetMethod('Name').Invoke($null, @(args))` reducing to `[Type]::Name(args)`.
- Instance reflection method invocation unwrapping for `$obj.GetType().GetMethod('Name').Invoke($obj, @(args))` reducing to `$obj.Name(args)`.
- Dynamic member access and method invocation support (`$obj.('Substring')(0, 5)` -> `$obj.Substring(0, 5)`, `[Type]::('Method')(args)` -> `[Type]::Method(args)`) with AST primitives `DynamicMemberAccessNode`, `DynamicMethodCallNode`, and `DynamicStaticMemberAccessNode`.
- Property and field reflection unwrapping for `GetProperty('Name').GetValue(...)`, `GetField('Name').GetValue(...)`, and `SetValue(...)` reducing to clean property access and assignments (`[Type]::Field = value`).
- Symbol table variable tracking for multi-step reflection definitions (`$m = [Type].GetMethod('Name'); $m.Invoke(...)`).
- Static reduction of `[System.Type]::GetType('FullType')` and `[type]'FullType'` to canonical type references (`[FullType]`).
- ScriptBlock `.Invoke()` reduction unwrapping standalone `{ ... }.Invoke()` expressions into direct statement executions or call operators (`&`).
- Pure .NET string instance methods constant folding (`Substring`, `ToLower`, `ToUpper`, `Trim`, `TrimStart`, `TrimEnd`, `Replace`, `Split`, `Contains`, `StartsWith`, `EndsWith`, `IndexOf`, `LastIndexOf`, `PadLeft`, `PadRight`, `Insert`, `Remove`, `Length`).
- Pure .NET static methods constant folding for `[System.String]` (`Concat`, `Join`, `IsNullOrEmpty`, `IsNullOrWhiteSpace`) and `[System.Math]` (`Abs`, `Min`, `Max`).
- Memory zeroization and safety bounds checks preventing out-of-range index crashes and surrogate corruptions.
- Comprehensive unit and integration test suite (`tests/test_reflection_unwrapper.py`) expanding total repository test coverage to 93 tests passing with 100% success.

## [0.4.0] - 2026-10-13

### Added
- Environment variable and ExecutionContext inlining engine (`src/environment_inliner.py`) providing compiler-grade constant propagation for obfuscated PowerShell scripts.
- Constant inlining for Windows environment variables (`$env:COMSPEC`, `$env:PATH`, `$env:PATHEXT`, `$env:SYSTEMROOT`, `$env:WINDIR`, `$env:PUBLIC`, `$env:TEMP`, etc.) with support for custom runtime dictionaries and dynamic assignment tracking (`$env:VAR = 'val'`).
- Inlining for PowerShell automatic and preference variables (`$PSHOME`, `$ShellId`, `$Host`, `$VerbosePreference`, `$ConfirmPreference`, `$ErrorActionPreference`, `$DebugPreference`).
- Character-level array indexing and slice recovery on environment variables and preferences (`$env:COMSPEC[4,15,25] -join ''` -> `'iex'`).
- Deep `$ExecutionContext` and `$ExecutionContext.InvokeCommand` static method unwrapping (`InvokeScript`, `NewScriptBlock`, `ExpandString`, `GetCommand`, `GetCmdlet`, `ToString`).
- ExecutionContext SessionState navigation (`$ExecutionContext.SessionState.LanguageMode` -> `'FullLanguage'`, `$ExecutionContext.SessionState.Path`).
- Call operator (`&`) and dot-source (`.`) simplification reducing indirect cmdlet calls (`& 'iex' 'script'` -> `iex 'script'`).
- Interpolated string variable expansion for double-quoted template expressions (`"Path: $env:SYSTEMROOT\system32"` -> `"Path: C:\Windows\system32"`).
- Comprehensive unit and integration test suite (`tests/test_environment_inliner.py`) expanding total test coverage to 73 tests passing with zero regressions.

## [0.3.0] - 2026-10-13

### Added
- Type Accelerator registry (`src/type_accelerators.py`) mapping PowerShell shorthand type aliases (`char`, `byte[]`, `int`, `string`, `convert`, `type`, `regex`) to full .NET type definitions with case-insensitive normalization.
- Type casting mangling resolver (`src/type_casting_resolver.py`) evaluating `[char]`, `[char[]]`, `[byte]`, `[byte[]]`, `[int]`, and `[string]` casts to canonical literals.
- Array indexing, slice shuffling, and reverse range evaluation (`'olleh'[-1..-5] -join ''`, `'olleh'[4..0]`, `[char[]](88,69,73)[2,1,0]`).
- PowerShell `-join` operator AST normalization supporting both unary (`-join expr`) and binary (`expr -join delimiter`) joining.
- Static member method folding for `[System.Convert]` (`ToInt32`, `ToChar`, `FromBase64String`), `[System.String]` (`Join`, `Concat`), and `[System.Text.Encoding]` (`ASCII.GetString`, `UTF8.GetString`, `Unicode.GetString`).
- .NET type reflection unwrapping for `[type]"System.String"` and metadata access (`.Name`, `.FullName`).
- New AST node primitives `IndexAccessNode` and `UnaryOpNode` integrated into recursive descent parser and code serializer.
- Comprehensive unit and integration test suite (`tests/test_type_casting.py`) expanding total test coverage to 58 tests passing with zero regressions.

## [0.2.0] - 2026-10-13

### Added
- SecureString cryptographic emulation engine (`src/secure_string_crypto.py`) parsing standard Windows PowerShell envelope formats (`76492d1116743f0423413b16050a5345...`).
- AES-128, AES-192, and AES-256 CBC decryption with PKCS#7 unpadding and pure-Python zero-dependency fallback engine.
- Static key extraction subsystem (`src/static_key_extractor.py`) recovering keys from range expressions (`1..16`, `1..32`), array literals (`@(1,2,...)`), type-casted byte arrays (`[byte[]](1..16)`), and tracked variables.
- AST reduction engine (`src/secure_string_reducer.py`) resolving `ConvertTo-SecureString` invocations, `[System.Runtime.InteropServices.Marshal]` BSTR pointers (`PtrToStringAuto`, `PtrToStringBSTR`, `PtrToStringUni`), and credential password access (`PSCredential`, `NetworkCredential`).
- Memory zeroization utility (`zeroize_buffer`) scrubbing key material and decrypted byte buffers immediately after processing.
- Extended unit test suite (`tests/test_secure_string.py`) expanding total test coverage to 34 tests passing with zero regressions.

## [0.1.0] - 2026-10-13

### Added
- Initial project architecture and core compiler pipeline.
- Token specifications and lexer (`src/tokens.py`, `src/lexer.py`) modeling PowerShell character scanning, string literals, and variable identifiers.
- Abstract Syntax Tree node hierarchy (`src/ast_nodes.py`) and recursive descent parser (`src/parser.py`).
- Normalization engine (`src/normalizer.py`) implementing backtick escape stripping, string concatenation folding, and format operator (`-f`) evaluation.
- Fixed-point multi-pass deobfuscator engine (`src/deobfuscator_engine.py`).
- Command-line interface (`src/cli.py`) supporting CLI deobfuscation and AST dumping.
- Comprehensive unit test suite with 100% pass verification.
