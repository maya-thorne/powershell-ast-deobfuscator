# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for `powershell-ast-deobfuscator`.

---

## Shipped Capabilities

- [x] **Core PowerShell AST Architecture & Lexer** — Character-level tokenization, backtick escape normalization, format string (`-f`) constant folding, string concatenation reduction, and initial unit test suite.
- [x] **SecureString & ConvertTo-SecureString Emulation** — Standard envelope parsing (`76492d11...`), AES-CBC decryption, static key extractor (ranges, array literals, byte casts), Marshal BSTR and credential password unwrapping, and memory zeroization.
- [x] **Type Accelerator & Type Casting Mangling Resolver** — Resolution of shorthand type accelerators (`[type]`, `[char[]]`, `[int]`, `[byte[]]`), array index shuffling, reverse slices, join operators (`-join`), static conversion methods (`[Convert]`, `[Text.Encoding]`), and .NET type reflection unwrapping.

---

## Planned Milestones

- [ ] **Environment Variable & Special Variable Inlining** — Constant propagation for `$env:COMSPEC`, `$env:PATH`, and `$ExecutionContext`.
- [ ] **Member Access & Reflection Deobfuscation** — Static unwrapping of invoke expressions (`.Invoke()`, `::Invoke()`, reflection get-member patterns).
- [ ] **Pipeline & ScriptBlock Control Flow Normalizer** — Simplification of obfuscated pipes (`| %`, `| ForEach-Object`, `| Select-Object`).
- [ ] **PowerShell AST Export & ASCII/Mermaid Visualization** — Visual tree rendering CLI for triage and forensic reporting.
- [ ] **Base64 Encoded Command Unwrapper** — Detection and recursive decoding of `-e`, `-enc`, `-EncodedCommand` flags.
- [ ] **AST Anti-Evasion & String Re-joining Pass** — Neutralization of mixed-case fragmentation and subexpression splits.
- [ ] **Automated Deobfuscation Benchmark Runner** — 30-sample corpus evaluation harness with scoring metrics.
- [ ] **DownloadString & WebClient API Remote Payload Carving** — Static carving of obfuscated remote endpoint URLs.
- [ ] **Arithmetic & Bitwise Operator Static Folding** — Constant reduction for XOR, SHL, and SHR loops.
- [ ] **Recursive IEX Unwrapper & Execution Tree Flattener** — Multi-layered `iex(iex(...))` peeling.
- [ ] **AMSI & ETW Bypass Static Pattern Detection** — Signature detection and automatic deobfuscation of AmsiScanBuffer patch loops.
- [ ] **Runspace Pool & Multi-Thread Pipeline Decompiler** — Static decomposition of runspace-isolated background jobs.
