# Project Roadmap

This document tracks shipped capabilities and future engineering milestones for `powershell-ast-deobfuscator`.

---

## Shipped Capabilities

- [x] **Core PowerShell AST Architecture & Lexer (M01)** — Character-level tokenization, backtick escape normalization, format string (`-f`) constant folding, string concatenation reduction, and unit test suite.

---

## Planned Milestones

- [ ] **SecureString & ConvertTo-SecureString Emulation (M02)** — Static decryptor and AST reducer for encrypted standard strings.
- [ ] **Type Casting & Type Shortcut Resolver (M03)** — Resolution of obfuscated type accelerators (`[type]`, `[char[]]`, `[int]`, `[byte[]]`).
- [ ] **Environment Variable & Special Variable Inlining (M04)** — Constant propagation for `$env:COMSPEC`, `$env:PATH`, and `$ExecutionContext`.
- [ ] **Member Access & Reflection Deobfuscation (M05)** — Static unwrapping of invoke expressions (`.Invoke()`, `::Invoke()`, reflection get-member patterns).
- [ ] **Pipeline & ScriptBlock Control Flow Normalizer (M06)** — Simplification of obfuscated pipes (`| %`, `| ForEach-Object`, `| Select-Object`).
- [ ] **PowerShell AST Export & ASCII/Mermaid Visualization (M07)** — Visual tree rendering CLI for triage and forensic reporting.
- [ ] **Base64 Encoded Command Unwrapper (M08)** — Detection and recursive decoding of `-e`, `-enc`, `-EncodedCommand` flags.
- [ ] **AST Anti-Evasion & String Re-joining Pass (M09)** — Neutralization of mixed-case fragmentation and subexpression splits.
- [ ] **Automated Deobfuscation Benchmark Runner (M10)** — 30-sample corpus evaluation harness with scoring metrics.
