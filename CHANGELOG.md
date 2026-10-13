# Changelog

All notable changes to `powershell-ast-deobfuscator` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
