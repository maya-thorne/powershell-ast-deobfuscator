"""
PowerShell AST Mutation & Stress Fuzzing Engine.
Applies lexical, syntactic, and structural mutations to PowerShell scripts for fuzz testing.
"""

import random
import re
from typing import List, Optional, Tuple

from .fuzz_models import FuzzMutationRecord, FuzzTestCase, MutationStrategy


class PowerShellScriptMutator:
    """
    Deterministic mutator for generating randomized and adversarial PowerShell code variants.
    """

    def __init__(self, seed: Optional[int] = None):
        self.seed = seed if seed is not None else random.randint(1, 1000000)
        self.rng = random.Random(self.seed)

    def set_seed(self, seed: int) -> None:
        """Sets the random generator seed for deterministic reproducibility."""
        self.seed = seed
        self.rng = random.Random(seed)

    def inject_backticks(self, code: str, count: int = 5) -> Tuple[str, List[FuzzMutationRecord]]:
        """Injects random backtick escape characters inside identifiers and string literals."""
        records: List[FuzzMutationRecord] = []
        if not code:
            return code, records

        # Target alphanumeric words that are at least 2 characters long
        words = list(re.finditer(r"\b[A-Za-z][A-Za-z0-9_-]+\b", code))
        if not words:
            return code, records

        chars = list(code)
        # Choose candidate injection points
        chosen = self.rng.sample(words, min(count, len(words)))
        offset_shifts = 0

        # Sort chosen words by start position
        chosen.sort(key=lambda m: m.start())

        for match in chosen:
            start, end = match.start() + offset_shifts, match.end() + offset_shifts
            if end - start > 2:
                insert_idx = start + self.rng.randint(1, end - start - 1)
                chars.insert(insert_idx, "`")
                offset_shifts += 1
                records.append(
                    FuzzMutationRecord(
                        strategy=MutationStrategy.BACKTICK_INJECTION,
                        description=f"Injected backtick into '{match.group(0)}'",
                        offset=insert_idx,
                    )
                )

        return "".join(chars), records

    def scramble_case(self, code: str, ratio: float = 0.5) -> Tuple[str, List[FuzzMutationRecord]]:
        """Randomly toggles letter casing in identifiers, cmdlets, and keywords."""
        records: List[FuzzMutationRecord] = []
        if not code:
            return code, records

        chars = list(code)
        mutated_count = 0
        in_single_quote = False

        for i, ch in enumerate(chars):
            if ch == "'":
                in_single_quote = not in_single_quote
                continue

            if not in_single_quote and ch.isalpha():
                if self.rng.random() < ratio:
                    chars[i] = ch.lower() if ch.isupper() else ch.upper()
                    mutated_count += 1

        if mutated_count > 0:
            records.append(
                FuzzMutationRecord(
                    strategy=MutationStrategy.CASE_SCRAMBLE,
                    description=f"Randomized casing across {mutated_count} characters",
                    metadata={"characters_mutated": mutated_count},
                )
            )

        return "".join(chars), records

    def mutate_whitespace(self, code: str, count: int = 5) -> Tuple[str, List[FuzzMutationRecord]]:
        """Injects varied whitespace variations (tabs, multiple spaces, CRLF, backtick newlines)."""
        records: List[FuzzMutationRecord] = []
        if not code:
            return code, records

        whitespace_variants = ["   ", "\t", "\t\t", "\r\n", " `\r\n", " `\n "]
        chars = list(code)
        applied = 0

        for _ in range(count):
            if not chars:
                break
            idx = self.rng.randint(0, len(chars))
            variant = self.rng.choice(whitespace_variants)
            chars.insert(idx, variant)
            applied += 1

        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.WHITESPACE_MUTATION,
                description=f"Injected {applied} varied whitespace / newline sequences",
                metadata={"injections": applied},
            )
        )
        return "".join(chars), records

    def inject_comments(self, code: str, count: int = 3) -> Tuple[str, List[FuzzMutationRecord]]:
        """Injects inline single-line and block comments at statement or token boundaries."""
        records: List[FuzzMutationRecord] = []
        if not code:
            return code, records

        comment_templates = [
            "<# fuzz-decoy #>",
            "<# [STRESS-BLOCK] #>",
            "# auto-injected-comment\n",
            "<#\r\n  multiline comment\r\n#>",
        ]

        chars = list(code)
        for _ in range(count):
            idx = self.rng.randint(0, len(chars))
            c = self.rng.choice(comment_templates)
            chars.insert(idx, f" {c} ")
            records.append(
                FuzzMutationRecord(
                    strategy=MutationStrategy.COMMENT_INJECTION,
                    description=f"Injected comment: {c.strip()[:20]}",
                    offset=idx,
                )
            )

        return "".join(chars), records

    def stress_nesting(self, code: str, depth: int = 5) -> Tuple[str, List[FuzzMutationRecord]]:
        """Wraps expressions in deeply nested parentheses, subexpressions, or array brackets."""
        records: List[FuzzMutationRecord] = []
        if not code.strip():
            return code, records

        wrappers = [
            ("$(", ")"),
            ("(", ")"),
            ("@(", ")"),
        ]

        res = code.strip()
        for i in range(min(depth, 50)):
            opening, closing = self.rng.choice(wrappers)
            res = f"{opening}{res}{closing}"

        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.NESTING_STRESS,
                description=f"Nested code inside {depth} layers of expression wrappers",
                metadata={"depth": depth},
            )
        )
        return res, records

    def shuffle_format_strings(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Splits string literals into randomized format operator expressions ('-f')."""
        records: List[FuzzMutationRecord] = []
        matches = list(re.finditer(r"'([^'\r\n]{3,})'", code))
        if not matches:
            return code, records

        target = self.rng.choice(matches)
        raw_text = target.group(1)
        k = min(len(raw_text), 3)
        chunk_len = max(1, len(raw_text) // k)
        chunks = [raw_text[i:i + chunk_len] for i in range(0, len(raw_text), chunk_len)]
        indices = list(range(len(chunks)))
        self.rng.shuffle(indices)

        fmt_str = "".join(f"{{{idx}}}" for idx in indices)
        inv_args = [None] * len(chunks)
        for original_pos, shuffled_idx in enumerate(indices):
            inv_args[shuffled_idx] = chunks[original_pos]

        args_str = ", ".join(f"'{c}'" for c in inv_args)
        replacement = f"('{fmt_str}' -f {args_str})"

        mutated = code[:target.start()] + replacement + code[target.end():]
        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.FORMAT_STRING_SHUFFLE,
                description=f"Converted '{raw_text}' into shuffled format expression",
                metadata={"chunks": len(chunks)},
            )
        )
        return mutated, records

    def split_and_concat_strings(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Splits string literals into concatenated chunks ('a' + 'b' + 'c')."""
        records: List[FuzzMutationRecord] = []
        matches = list(re.finditer(r"'([^'\r\n]{2,})'", code))
        if not matches:
            return code, records

        target = self.rng.choice(matches)
        raw = target.group(1)
        split_pt = self.rng.randint(1, len(raw) - 1)
        part1 = raw[:split_pt]
        part2 = raw[split_pt:]
        replacement = f"('{part1}' + '{part2}')"

        mutated = code[:target.start()] + replacement + code[target.end():]
        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.STRING_SPLIT_CONCAT,
                description=f"Split string into ('{part1}' + '{part2}')",
                offset=target.start(),
            )
        )
        return mutated, records

    def mangle_array_expressions(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Adds comma array syntax, unary comma `,expr`, or indexing."""
        records: List[FuzzMutationRecord] = []
        if not code.strip():
            return code, records

        variants = [
            f",({code})",
            f"@({code})[0]",
            f"({code}, 'decoy')[0]",
            f"(({code})[-1..0])[-1]",
        ]
        res = self.rng.choice(variants)
        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.ARRAY_MANGLE,
                description="Mangled array wrapping / unary comma index access",
            )
        )
        return res, records

    def mangle_type_accelerators(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Injects casing, backticks, and namespaces into type accelerators."""
        records: List[FuzzMutationRecord] = []
        accelerators = ["[char[]]", "[byte[]]", "[string]", "[int32]", "[System.Convert]", "[System.Text.Encoding]"]
        matches = list(re.finditer(r"\[[A-Za-z0-9_.\[\]]+\]", code))

        if matches:
            target = self.rng.choice(matches)
            orig = target.group(0)
            inner = orig[1:-1]
            chars = list(inner)
            if len(chars) > 2:
                chars.insert(self.rng.randint(1, len(chars) - 1), "`")
            mangled = "[" + "".join(chars) + "]"
            mutated = code[:target.start()] + mangled + code[target.end():]
            records.append(
                FuzzMutationRecord(
                    strategy=MutationStrategy.TYPE_MANGLE,
                    description=f"Mangled type accelerator {orig} -> {mangled}",
                )
            )
            return mutated, records

        # If no type accelerator present, prepend a dummy cast expression
        chosen_acc = self.rng.choice(accelerators)
        res = f"({chosen_acc}('{code.strip()}'.ToCharArray()) -join '')" if "'" in code else f"{chosen_acc}({code})"
        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.TYPE_MANGLE,
                description=f"Wrapped code in {chosen_acc} type accelerator expression",
            )
        )
        return res, records

    def inject_unicode_edges(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Injects non-breaking spaces, zero-width spaces, or BOM marks."""
        records: List[FuzzMutationRecord] = []
        if not code:
            return code, records

        unicode_artifacts = [
            "\u200B",  # zero-width space
            "\u00A0",  # non-breaking space
            "\uFEFF",  # byte order mark
        ]
        chars = list(code)
        artifact = self.rng.choice(unicode_artifacts)
        idx = self.rng.randint(0, len(chars))
        chars.insert(idx, artifact)

        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.UNICODE_EDGE,
                description=f"Injected unicode codepoint U+{ord(artifact):04X}",
                offset=idx,
            )
        )
        return "".join(chars), records

    def corrupt_syntax(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Intentionally introduces malformed syntax to verify graceful error handling."""
        records: List[FuzzMutationRecord] = []
        if not code:
            return code, records

        corruption_modes = ["drop_quote", "unclosed_brace", "dangling_pipe", "trailing_operator"]
        mode = self.rng.choice(corruption_modes)

        if mode == "drop_quote" and "'" in code:
            idx = code.rfind("'")
            mutated = code[:idx] + code[idx + 1:]
            desc = "Removed closing single quote"
        elif mode == "unclosed_brace":
            mutated = code + " { "
            desc = "Appended unclosed opening curly brace"
        elif mode == "dangling_pipe":
            mutated = code.strip() + " | "
            desc = "Appended dangling pipeline pipe"
        else:
            mutated = code.strip() + " -f "
            desc = "Appended dangling binary format operator"

        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.SYNTAX_CORRUPTION,
                description=desc,
                metadata={"corruption_mode": mode},
            )
        )
        return mutated, records

    def inject_decoys(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Injects dead code branches, while(false) loops, and unused variables."""
        records: List[FuzzMutationRecord] = []
        decoys = [
            "; if ($false) { Write-Output 'unreachable decoy' }; ",
            "; while ($false) { $decoy = 123 }; ",
            "; $decoyVar_99 = 'dead code decoy payload'; ",
            "; try { } catch { $decoyDummy = 1 }; ",
        ]
        decoy = self.rng.choice(decoys)
        mutated = code + decoy
        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.DECOY_INJECTION,
                description=f"Injected dead decoy code: {decoy.strip()[:30]}",
            )
        )
        return mutated, records

    def stress_ranges(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Injects PowerShell range expressions (..)."""
        records: List[FuzzMutationRecord] = []
        range_patterns = [
            "(1..10 | % { [char]($_ + 64) }) -join ''",
            "(-5..-1)",
            "(20..1)",
            "(0..0)",
        ]
        chosen = self.rng.choice(range_patterns)
        mutated = f"({chosen}); {code}"
        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.RANGE_STRESS,
                description=f"Prepended range expression: {chosen}",
            )
        )
        return mutated, records

    def chain_pipes(self, code: str) -> Tuple[str, List[FuzzMutationRecord]]:
        """Chains multiple pipeline stages."""
        records: List[FuzzMutationRecord] = []
        pipeline_stages = [
            " | Out-String",
            " | ForEach-Object { $_ }",
            " | Where-Object { $true }",
            " | Select-Object -First 10",
        ]
        stage = self.rng.choice(pipeline_stages)
        mutated = code.strip() + stage
        records.append(
            FuzzMutationRecord(
                strategy=MutationStrategy.PIPE_CHAIN,
                description=f"Chained pipeline stage: {stage.strip()}",
            )
        )
        return mutated, records

    def generate_mutated_case(
        self,
        original_code: str,
        name: str = "case",
        strategies: Optional[List[MutationStrategy]] = None,
        num_mutations: int = 3,
    ) -> FuzzTestCase:
        """Applies multiple mutation passes sequentially to construct a complete test case."""
        strategy_dispatch = {
            MutationStrategy.BACKTICK_INJECTION: self.inject_backticks,
            MutationStrategy.CASE_SCRAMBLE: self.scramble_case,
            MutationStrategy.WHITESPACE_MUTATION: self.mutate_whitespace,
            MutationStrategy.COMMENT_INJECTION: self.inject_comments,
            MutationStrategy.NESTING_STRESS: self.stress_nesting,
            MutationStrategy.FORMAT_STRING_SHUFFLE: self.shuffle_format_strings,
            MutationStrategy.STRING_SPLIT_CONCAT: self.split_and_concat_strings,
            MutationStrategy.ARRAY_MANGLE: self.mangle_array_expressions,
            MutationStrategy.TYPE_MANGLE: self.mangle_type_accelerators,
            MutationStrategy.UNICODE_EDGE: self.inject_unicode_edges,
            MutationStrategy.SYNTAX_CORRUPTION: self.corrupt_syntax,
            MutationStrategy.DECOY_INJECTION: self.inject_decoys,
            MutationStrategy.RANGE_STRESS: self.stress_ranges,
            MutationStrategy.PIPE_CHAIN: self.chain_pipes,
        }

        avail_strategies = strategies if strategies else list(strategy_dispatch.keys())
        current_code = original_code
        applied_records: List[FuzzMutationRecord] = []
        applied_strategies: List[MutationStrategy] = []

        for _ in range(num_mutations):
            strat = self.rng.choice(avail_strategies)
            handler = strategy_dispatch.get(strat)
            if handler:
                mutated_code, records = handler(current_code)
                current_code = mutated_code
                applied_records.extend(records)
                if strat not in applied_strategies:
                    applied_strategies.append(strat)

        test_id = f"fuzz_{self.seed:06d}_{name}"
        return FuzzTestCase(
            test_id=test_id,
            seed=self.seed,
            base_name=name,
            original_code=original_code,
            mutated_code=current_code,
            mutations=applied_records,
            target_strategies=applied_strategies,
        )

    def generate_adversarial_template(self, category: str = "nesting", depth: int = 20) -> str:
        """Synthesizes synthetic edge-case scripts from scratch for stress testing."""
        if category == "nesting":
            res = "'core_payload'"
            for _ in range(depth):
                res = f"$({res})"
            return res
        elif category == "format_shuffle":
            parts = [f"part_{i}" for i in range(15)]
            indices = list(range(len(parts)))
            self.rng.shuffle(indices)
            fmt = "".join(f"{{{idx}}}" for idx in indices)
            args = ", ".join(f"'{p}'" for p in parts)
            return f"('{fmt}' -f {args})"
        elif category == "xor_loop":
            return "(0..10 | % { $_ -bxor 0x5A })"
        else:
            return "Write-Output 'adversarial benchmark'"
