# Changelog

All notable changes to `powershell-ast-deobfuscator` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-13

### Added
- Initial project architecture and core compiler pipeline (M01).
- Token specifications and lexer (`src/tokens.py`, `src/lexer.py`) modeling PowerShell character scanning, string literals, and variable identifiers.
- Abstract Syntax Tree node hierarchy (`src/ast_nodes.py`) and recursive descent parser (`src/parser.py`).
- Normalization engine (`src/normalizer.py`) implementing backtick escape stripping, string concatenation folding, and format operator (`-f`) evaluation.
- Fixed-point multi-pass deobfuscator engine (`src/deobfuscator_engine.py`).
- Command-line interface (`src/cli.py`) supporting CLI deobfuscation and AST dumping.
- Comprehensive unit test suite with 100% pass verification.
