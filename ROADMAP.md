# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for `powershell-ast-deobfuscator`.

---

## Shipped Capabilities

- [x] **Core PowerShell AST Architecture & Lexer** — Character-level tokenization, backtick escape normalization, format string (`-f`) constant folding, string concatenation reduction, and initial unit test suite.
- [x] **SecureString & ConvertTo-SecureString Emulation** — Standard envelope parsing (`76492d11...`), AES-CBC decryption, static key extractor (ranges, array literals, byte casts), Marshal BSTR and credential password unwrapping, and memory zeroization.
- [x] **Type Accelerator & Type Casting Mangling Resolver** — Resolution of shorthand type accelerators (`[type]`, `[char[]]`, `[int]`, `[byte[]]`), array index shuffling, reverse slices, join operators (`-join`), static conversion methods (`[Convert]`, `[Text.Encoding]`), and .NET type reflection unwrapping.
- [x] **Environment Variable & ExecutionContext Inlining** — Constant propagation for Windows environment variables (`$env:COMSPEC`, `$env:PATH`, `$env:SYSTEMROOT`), automatic preference variables (`$PSHOME`, `$ShellId`, `$VerbosePreference`), array slice recovery (`$env:COMSPEC[4,15,25] -join ''` -> `'iex'`), `$ExecutionContext.InvokeCommand` method unwrapping, and call operator (`&`) reduction.
- [x] **Reflection & Dynamic Member Call Unwrapping** — Static unwrapping of reflection method invocations (`[Type].GetMethod('Name').Invoke(...)` -> `[Type]::Name(...)`), dynamic member expressions (`$obj.('Substring')(...)` -> `$obj.Substring(...)`), property/field reflection (`GetProperty`, `GetField`, `GetValue`, `SetValue`), pure .NET string & math constant evaluation, and scriptblock invoke reduction.
- [x] **Pipeline & ScriptBlock Control Flow Optimization** — Static evaluation of pipeline stages (`| %`, `| ForEach-Object`, `| Select-Object`, `| Where-Object`, `| Out-String`), ScriptBlock invocation unwrapping (`& { ... }`, `. { ... }`, `{ ... }.Invoke()`), conditional branch reduction (`if ($true)`, `if ($false)`), and piped command simplification (`'calc.exe' | iex` -> `iex 'calc.exe'`).
- [x] **PowerShell AST Export & ASCII/Mermaid Visualization** — Hierarchical syntax tree rendering in Unicode and ASCII (`src/ast_visualizer.py`), Mermaid flowchart diagram generation (`flowchart TD`), Graphviz DOT graph export, structured JSON hierarchy serialization, AST complexity metrics (`src/ast_exporter.py`), and CLI visualization flags (`--ast`, `--tree`, `--mermaid`, `--dot`, `--json`, `--stats`).
- [x] **Base64 Encoded Command Recursive Unwrapper** — Recursive extraction and decoding of `-e`, `-enc`, `-EncodedCommand` parameters across CLI strings and AST `CommandNode` structures, multi-encoding auto-detection (UTF-16LE, UTF-8, UTF-16BE, ASCII), Base64 padding auto-repair, loop protection via SHA-256 hash tracking, and Shannon entropy forensic telemetry (`src/encoded_command_unwrapper.py`).
- [x] **Subexpression Splitting & Casing Randomization Normalizer** — Subexpression (`$(...)`) unboxing and flattening, redundant nested wrapper stripping (`$((('cmd.exe')))`), concatenation folding inside subexpressions, expandable string interpolation, local assignment propagation (`$($x='calc'; $x)`), subexpression indexing (`$('abc')[1]`), canonical casing restoration for 46 approved PowerShell verbs, 150+ cmdlets and aliases, language keywords, .NET type accelerators and classes (`[byte[]]`, `[System.Net.WebClient]`), instance and static method calls, CLI parameters (`-EncodedCommand`), and automatic/environment variables (`$true`, `$false`, `$null`, `$env:COMSPEC`) (`src/subexpression_unwrapper.py`, `src/casing_normalizer.py`).
- [x] **Automated Deobfuscation Benchmark Runner & Accuracy Harness** — Curated 30-sample obfuscated PowerShell corpus across 10 evasion categories, multi-dimensional fidelity telemetry (Shannon entropy, artifact reduction, ground-truth indicator recall, AST syntax validity), composite fidelity scoring (0-100%), ASCII/JSON/Markdown report generation, and CLI benchmark execution flags (`--benchmark`, `--benchmark-sample`, `--benchmark-category`, `--benchmark-report`, `--benchmark-format`) (`src/benchmark.py`, `src/benchmark_corpus.py`, `src/benchmark_metrics.py`, `src/benchmark_runner.py`).
- [x] **DownloadString & WebClient API Remote Payload Carving** — Compiler-grade AST static tracing and heuristic URL carving for WebClient, HttpClient, HttpWebRequest, and download cmdlets (`Invoke-WebRequest`, `iwr`, `Invoke-RestMethod`, `irm`, `Start-BitsTransfer`), resolving obfuscated decimal/DWORD, hexadecimal, octal, and dotted IPs, tracking headers and proxies, detecting download cradles (`iex_download_string`, `file_download_execute`, `in_memory_assembly_load`), and CLI integration (`--carve-urls`, `--urls`) (`src/webclient_tracer.py`).
- [x] **Arithmetic & Bitwise Operator Static Folding & XOR Loop Decryptor** — Compiler-grade static constant evaluation for bitwise (`-bxor`, `-band`, `-bor`, `-shl`, `-shr`, `-bnot`), arithmetic (`+`, `-`, `*`, `/`, `%`), comparisons (`-eq`, `-ne`, `-gt`, `-ge`, `-lt`, `-le`), and pipeline/imperative XOR loop static decryption engine with single/multi-byte key recovery, encoding wrappers, and zeroize memory wiping (`src/bitwise_folding_engine.py`, `src/xor_loop_decryptor.py`).
- [x] **Recursive IEX Unwrapper & Execution Tree Flattener** — Multi-layered `iex(iex(...))` peeling across direct cmdlets, dot/call operators, ScriptBlock API invocations (`[scriptblock]::Create($code).Invoke()`), `$ExecutionContext.InvokeCommand.InvokeScript`, multi-stage pipeline streaming (`... | iex | iex`), dynamic download cradle retention, cycle detection via SHA-256 hash tracking, and layer extraction telemetry (`--trace-iex`) (`src/iex_unwrapper.py`).

---

## Planned Milestones

- [ ] **AMSI & ETW Bypass Static Pattern Detection** — Signature detection and automatic deobfuscation of AmsiScanBuffer patch loops.
- [ ] **Runspace Pool & Multi-Thread Pipeline Decompiler** — Static decomposition of runspace-isolated background jobs.
- [ ] **COM Object CLSID & ProgID Inlining Engine** — Static resolution of WScript.Shell, Shell.Application, and ADODB stream obfuscation patterns.
- [ ] **Clipboard & Keystroke In-Memory Buffer Tracking** — Static pattern tracking and carving for API keystroke capture routines.
- [ ] **PowerShell Authenticode Signature Bypass Validation** — Static detection and stripping of tampered digital signature evasion blocks.
- [ ] **PowerShell 7.4+ ForEach-Object -Parallel Pipeline Analyzer** — Static decomposition of parallelized worker scriptblocks and concurrent task pools.
- [ ] **Constrained Language Mode (CLM) Policy Bypass Analyzer** — Static validation of language mode boundary enforcement and `__PSLockdownPolicy` tampering patterns.
- [ ] **.NET Assembly Reflection Loader (Assembly.Load) In-Memory PE Parser** — Static carving of byte arrays and in-memory .NET PE header metadata reconstruction.
- [ ] **Dynamic Obfuscation Transaction Snapshot Rollback Engine** — Conditional execution path branch tracking and variable state convergence analysis.
- [ ] **PowerShell Virtual Machine AST Intermediate Representation (IR) Normalizer** — SSA-form intermediate representation lowering and dead code elimination.
- [ ] **PowerShell ETW Event Provider (Event 4104) Static De-tampering Engine** — Static reconstruction of patched ETW event provider handles and telemetry unhooking.
- [ ] **PowerShell Remote Target PSSession & WSMan Payload Unwrapping** — Static decomposition of Enter-PSSession and Invoke-Command serialized CLIXML payloads.
- [ ] **PowerShell Custom Type Provider & Accelerator Poisoning Analyzer** — Static detection of poisoned type accelerators and hijacked type tables.
- [ ] **PowerShell .NET AppDomain & AssemblyResolve Dynamic Hook Tracer** — Static decomposition of custom assembly resolution and encrypted resource packers.
- [ ] **PowerShell AMSI Memory Patching Multi-Pattern Analyzer** — Static detection and signature extraction for AmsiScanBuffer, AmsiInitialize, and AmsiOpenSession memory patching.
- [ ] **Constrained Language Mode (CLM) Escape Simulator** — Static modeling of execution pathways and policy boundary bypass verification.
- [ ] **PowerShell .NET P/Invoke & DllImport Native Windows API Resolver** — Static detection and signature extraction for kernel32/ntdll memory injection primitives.
- [ ] **PowerShell Variable Scope Mangle & ExecutionContext Inliner** — Reverse tracking of execution path and calling context obfuscation.
- [ ] **PowerShell AST-Based Control Flow Flattening (CFF) De-dispatcher** — State-machine-based switch-case and while loop dispatcher deobfuscation engine.
- [ ] **PowerShell 7.4+ Pipeline Chain Operator (&& / ||) Control Flow Normalizer** — Static analysis and conditional branch simplification for short-circuit pipeline chains.
- [ ] **In-Memory .NET Delegate & Reflection Dynamic Invocation Tracker** — Static recovery of obfuscated delegate bindings and function pointer invocations.
- [ ] **AMSI Context Structure Corruption Detector & Static Heuristic Analyzer** — Static detection and pattern matching for in-memory AmsiContext corruption evasion.

