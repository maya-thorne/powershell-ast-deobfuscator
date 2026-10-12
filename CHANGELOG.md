# Changelog

All notable changes to `powershell-ast-deobfuscator` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
