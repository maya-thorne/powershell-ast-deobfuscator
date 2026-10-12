# PowerShell AST Deobfuscator

<p align="center">
  <img src="docs/assets/banner.svg" alt="PowerShell AST Deobfuscator Banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/maya-thorne/powershell-ast-deobfuscator"><img src="https://img.shields.io/badge/Release-v0.1.0-blue.svg?style=flat-square" alt="Release v0.1.0" /></a>
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

Modern PowerShell malware heavily exploits multi-layer obfuscation, such as backtick (`` ` ``) token evasion, scattered string concatenation (`+`), format operator (`-f`) template permutations, type accelerator shuffling, and nested Base64 command flags. This suite models PowerShell syntax directly down to tokens and AST nodes, systematically normalizing obfuscated structures into clean, human-readable source code.

---

<span id="pipeline-architecture"></span>
## 🏛️ Pipeline Architecture

<p align="center">
  <img src="docs/assets/pipeline_architecture.svg" alt="Pipeline Architecture" width="100%" />
</p>

The deobfuscation engine executes a multi-pass fixed-point reduction loop:

1. **Lexical Scanning (`src/lexer.py`)**: Tokenizes PowerShell code character-by-character, resolving backtick escape sequences, string literals, and variable identifiers.
2. **Recursive Descent Parsing (`src/parser.py`)**: Converts token streams into structured AST hierarchies (`ScriptBlockNode`, `PipelineNode`, `FormatOpNode`, `CommandNode`).
3. **AST Normalization &amp; Constant Folding (`src/normalizer.py`)**: Inlines string formats (`-f`), collapses string concatenations, strips parentheses artifacts, and serializes clean syntax.
4. **Fixed-Point Convergence (`src/deobfuscator_engine.py`)**: Iterates reduction passes until the code reaches a stable, non-mutating fixed point.

---

<span id="core-capabilities"></span>
## ⚡ Core Capabilities

| Capability | Obfuscated Example | Deobfuscated Output |
|---|---|---|
| **Backtick Evasion Stripping** | `In`voke-Exp`ression 'Get-Process'` | `Invoke-Expression 'Get-Process'` |
| **Format Operator (`-f`) Folding** | `'{1}{0}' -f 'World', 'Hello '` | `'Hello World'` |
| **String Concatenation Reduction** | `'Down' + 'load' + 'String'` | `'DownloadString'` |
| **Nested Composite Resolution** | `('{1}{0}' -f ('l'+'d'), ('Wor'+''))` | `'World'` |
| **Base64 EncodedCommand Decode** | `powershell.exe -enc VwBy...` | `powershell.exe -Command "Write-Host Success"` |

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
| `src/deobfuscator_engine.py` | Multi-pass fixed-point convergence engine |
| `src/cli.py` | Command-line interface with AST and token inspection flags |
| `tests/` | Comprehensive unit test suite covering lexer, parser, normalizer, and engine |
| `ROADMAP.md` | Public development milestones and engineering roadmap |
| `SECURITY.md` | Vulnerability disclosure policy and reporting process |

---

<span id="verification--tests"></span>
## 📊 Verification &amp; Tests

Run the full automated test suite:

```bash
python -m unittest discover tests -v
```

All 19 unit tests execute with zero failures:

```text
test_token_creation (test_tokens.TestTokens) ... ok
test_token_repr (test_tokens.TestTokens) ... ok
test_backtick_in_identifier (test_lexer.TestPowerShellLexer) ... ok
test_comments_stripping (test_lexer.TestPowerShellLexer) ... ok
test_double_quoted_string_with_backtick (test_lexer.TestPowerShellLexer) ... ok
test_format_operator (test_lexer.TestPowerShellLexer) ... ok
test_numbers (test_lexer.TestPowerShellLexer) ... ok
test_single_quoted_string (test_lexer.TestPowerShellLexer) ... ok
test_variables (test_lexer.TestPowerShellLexer) ... ok
test_parse_assignment (test_parser.TestPowerShellParser) ... ok
test_parse_binary_concatenation (test_parser.TestPowerShellParser) ... ok
test_parse_format_op (test_parser.TestPowerShellParser) ... ok
test_parse_pipeline (test_parser.TestPowerShellParser) ... ok
test_fold_format_operator (test_normalizer.TestPowerShellNormalizer) ... ok
test_fold_string_concatenation (test_normalizer.TestPowerShellNormalizer) ... ok
test_to_source_serialization (test_normalizer.TestPowerShellNormalizer) ... ok
test_backtick_obfuscation_removal (test_deobfuscator.TestPowerShellDeobfuscator) ... ok
test_base64_encoded_command_unwrapping (test_deobfuscator.TestPowerShellDeobfuscator) ... ok
test_nested_format_and_concat (test_deobfuscator.TestPowerShellDeobfuscator) ... ok

----------------------------------------------------------------------
Ran 19 tests in 0.005s

OK
```

---

<span id="usage"></span>
## 🚀 Usage

### Command-Line Interface

Deobfuscate a raw string or file:

```bash
# Direct inline string
python -m src.cli "('{1}{0}' -f 'World', 'Hello ')"

# Script file input with output redirection
python -m src.cli malicious_sample.ps1 -o cleaned_sample.ps1

# Inspect token stream
python -m src.cli "Invoke-Expression" --tokens

# Inspect AST tree
python -m src.cli "$x = 'test' + 'ing'" --ast
```

### Python API

```python
from src.deobfuscator_engine import PowerShellDeobfuscator

engine = PowerShellDeobfuscator()
raw_code = "In`voke-Exp`ression ('{1}{0}' -f 'ing', 'DownloadStr')"
cleaned_code = engine.deobfuscate(raw_code)

print(cleaned_code)
# Output: Invoke-Expression 'DownloadString'
```

---

## 📜 License

This project is licensed under the **Maya Thorne Systems &amp; Security Research License (MT-SRL)**. See [LICENSE](LICENSE) for details.
