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

---

## Planned Milestones

- [ ] **PowerShell AST Export & ASCII/Mermaid Visualization** — Visual tree rendering CLI for triage and forensic reporting.
- [ ] **Base64 Encoded Command Unwrapper** — Detection and recursive decoding of `-e`, `-enc`, `-EncodedCommand` flags.
- [ ] **AST Anti-Evasion & String Re-joining Pass** — Neutralization of mixed-case fragmentation and subexpression splits.
- [ ] **Automated Deobfuscation Benchmark Runner** — 30-sample corpus evaluation harness with scoring metrics.
- [ ] **DownloadString & WebClient API Remote Payload Carving** — Static carving of obfuscated remote endpoint URLs.
- [ ] **Arithmetic & Bitwise Operator Static Folding** — Constant reduction for XOR, SHL, and SHR loops.
- [ ] **Recursive IEX Unwrapper & Execution Tree Flattener** — Multi-layered `iex(iex(...))` peeling.
- [ ] **AMSI & ETW Bypass Static Pattern Detection** — Signature detection and automatic deobfuscation of AmsiScanBuffer patch loops.
- [ ] **Runspace Pool & Multi-Thread Pipeline Decompiler** — Static decomposition of runspace-isolated background jobs.
- [ ] **COM Object CLSID & ProgID Inlining Engine** — Static resolution of WScript.Shell, Shell.Application, and ADODB stream obfuscation patterns.
- [ ] **Clipboard & Keystroke In-Memory Buffer Tracking** — Static pattern tracking and carving for API keystroke capture routines.
- [ ] **PowerShell Authenticode Signature Bypass Validation** — Static detection and stripping of tampered digital signature evasion blocks.
