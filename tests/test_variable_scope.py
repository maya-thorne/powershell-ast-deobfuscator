"""
Comprehensive Unit & Integration Tests for Variable Scope Chain & Lifecycle Analysis Engine.
Covers local/script/global scopes, private isolation, shadowing, def-use chains,
PowerShell variable cmdlets (Set-Variable, Get-Variable, New-Variable), constant propagation,
dead variable elimination, forensic telemetry summaries, and CLI integration.
"""

import json
import os
import subprocess
import sys
import unittest

from src.ast_nodes import NumberLiteralNode, ScriptBlockNode, StringLiteralNode, VariableNode
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.scope_chain import PowerShellScopeChain
from src.scope_models import ScopeType
from src.variable_lifecycle_tracker import PowerShellVariableLifecycleTracker
from src.variable_scope import (
    analyze_scopes,
    export_scope_json,
    inline_scoped_variables,
    to_scope_report,
)
from src.variable_scope_inliner import PowerShellVariableScopeInliner


class TestVariableScopeChain(unittest.TestCase):
    """Tests core PowerShellScopeChain resolution and hierarchy behavior."""

    def test_global_and_script_initial_frames(self):
        chain = PowerShellScopeChain()
        self.assertEqual(chain.global_frame.scope_type, ScopeType.GLOBAL)
        self.assertEqual(chain.script_frame.scope_type, ScopeType.SCRIPT)
        self.assertEqual(chain.current_scope.scope_type, ScopeType.SCRIPT)
        self.assertIn(chain.script_frame, chain.global_frame.children)

    def test_qualified_global_write_and_read(self):
        chain = PowerShellScopeChain()
        sym, def_obj = chain.resolve_write("testVar", scope_qualifier="global", value="payload123", is_constant=True)
        self.assertEqual(sym.scope_type, ScopeType.GLOBAL)
        self.assertEqual(def_obj.value, "payload123")

        # Read using $global:testVar
        read_sym, read_obj = chain.resolve_read("testVar", scope_qualifier="global")
        self.assertIsNotNone(read_sym)
        self.assertEqual(read_sym.scope_id, chain.global_frame.scope_id)
        self.assertEqual(read_obj.reaching_definition_id, def_obj.definition_id)
        self.assertIn(read_obj.read_id, def_obj.reader_ids)

    def test_qualified_script_scope(self):
        chain = PowerShellScopeChain()
        sym, def_obj = chain.resolve_write("scriptVar", scope_qualifier="script", value=42, is_constant=True)
        self.assertEqual(sym.scope_type, ScopeType.SCRIPT)

        read_sym, read_obj = chain.resolve_read("scriptVar", scope_qualifier="script")
        self.assertEqual(read_sym.scope_id, chain.script_frame.scope_id)
        self.assertEqual(read_obj.reaching_definition_id, def_obj.definition_id)

    def test_private_variable_isolation(self):
        chain = PowerShellScopeChain()
        # Define private variable in script frame
        chain.resolve_write("secretKey", scope_qualifier="private", value="supersecret", is_constant=True)

        # In current (script) frame, private variable is accessible
        sym, read_obj = chain.resolve_read("secretKey")
        self.assertIsNotNone(sym)
        self.assertFalse(read_obj.is_uninitialized)

        # Enter child scriptblock frame
        chain.push_scope(ScopeType.SCRIPT_BLOCK, "child_block")
        # In child frame, unqualified lookup cannot see parent's private variable!
        child_sym, child_read = chain.resolve_read("secretKey")
        self.assertTrue(child_read.is_uninitialized)
        chain.pop_scope()

    def test_variable_shadowing_detection(self):
        chain = PowerShellScopeChain()
        # Outer definition in script frame
        outer_sym, _ = chain.resolve_write("shared", value="outer_val", is_constant=True)

        # Enter child scope
        child_frame = chain.push_scope(ScopeType.SCRIPT_BLOCK, "block_inner")
        # Local assignment with same name shadows outer symbol
        inner_sym, _ = chain.resolve_write("shared", value="inner_val", is_constant=True)

        self.assertTrue(inner_sym.is_shadowed)
        self.assertEqual(inner_sym.shadowed_scope_id, chain.script_frame.scope_id)
        self.assertNotEqual(outer_sym.scope_id, inner_sym.scope_id)
        chain.pop_scope()

    def test_dead_assignment_tracking(self):
        chain = PowerShellScopeChain()
        # $x = 1 (never read, immediately overwritten)
        _, def1 = chain.resolve_write("x", value=1, stmt_idx=1)
        # $x = 2 (read once)
        _, def2 = chain.resolve_write("x", value=2, stmt_idx=2)
        chain.resolve_read("x", stmt_idx=3)

        summary = chain.finalize_analysis()
        self.assertTrue(def1.is_dead)
        self.assertFalse(def2.is_dead)
        self.assertEqual(summary.dead_assignments_count, 1)

    def test_uninitialized_variable_read(self):
        chain = PowerShellScopeChain()
        sym, read_obj = chain.resolve_read("nonExistent")
        self.assertTrue(read_obj.is_uninitialized)
        summary = chain.finalize_analysis()
        self.assertEqual(summary.uninitialized_reads_count, 1)


class TestVariableLifecycleTracker(unittest.TestCase):
    """Tests AST traversal, cmdlet mapping, and lifecycle metrics calculation."""

    def test_variable_cmdlets_set_get(self):
        script = """
        Set-Variable -Name 'TargetUrl' -Value 'http://malware.test/payload.ps1' -Scope Global
        $url = Get-Variable -Name 'TargetUrl' -Scope Global
        """
        summary = analyze_scopes(script)
        self.assertGreaterEqual(summary.total_definitions, 2)
        self.assertGreaterEqual(summary.total_reads, 1)
        # Verify TargetUrl symbol recorded in global scope
        global_target = [s for s in summary.symbols_table if s["name"].lower() == "targeturl"]
        self.assertTrue(len(global_target) > 0)
        self.assertEqual(global_target[0]["constant_value"], "http://malware.test/payload.ps1")

    def test_cmdlet_aliases_sv_gv_nv(self):
        script = """
        nv MyConst -Value 1337 -Option Constant
        $val = gv MyConst
        sv MyOther 'test'
        """
        summary = analyze_scopes(script)
        const_syms = [s for s in summary.symbols_table if s["name"].lower() == "myconst"]
        self.assertTrue(len(const_syms) > 0)
        self.assertTrue(const_syms[0]["is_constant"])
        self.assertEqual(const_syms[0]["constant_value"], 1337)

    def test_foreach_loop_scope_lifecycle(self):
        script = """
        $list = 1, 2, 3
        foreach ($item in $list) {
            $inner = $item * 2
        }
        """
        summary = analyze_scopes(script)
        # Should create a child scope for the foreach loop
        self.assertGreater(summary.total_scopes, 2)
        # $inner is defined in child scope
        inner_sym = [s for s in summary.symbols_table if s["name"] == "inner"]
        self.assertTrue(len(inner_sym) > 0)
        self.assertNotEqual(inner_sym[0]["scope"], "script")

    def test_function_scope_declaration(self):
        script = """
        function Invoke-Payload {
            $localKey = 'secret123'
            $res = $localKey
        }
        """
        summary = analyze_scopes(script)
        func_scopes = [sc for sc in summary.scopes if "func:invoke-payload" in sc["name"].lower()]
        self.assertTrue(len(func_scopes) > 0)


class TestVariableScopeInliner(unittest.TestCase):
    """Tests constant propagation, cmdlet rewriting, and dead variable elimination."""

    def test_constant_propagation_single_variable(self):
        code = "$a = 'http://evil.com/drop.exe'; $b = $a"
        deobf = PowerShellDeobfuscator().deobfuscate(code)
        self.assertIn("'http://evil.com/drop.exe'", deobf)

    def test_constant_propagation_numeric(self):
        code = "$port = 8080; $res = $port + 1"
        deobf = PowerShellDeobfuscator().deobfuscate(code)
        self.assertIn("8081", deobf)

    def test_scoped_qualifier_constant_inlining(self):
        code = "$global:cmd = 'cmd.exe'; & $global:cmd"
        deobf = PowerShellDeobfuscator().deobfuscate(code)
        self.assertIn("cmd.exe", deobf)

    def test_shadowed_variable_distinct_inlining(self):
        code = """
        $x = 'outer'
        & {
            $x = 'inner'
            $test = $x
        }
        $out = $x
        """
        deobf = PowerShellDeobfuscator().deobfuscate(code)
        self.assertIn("'inner'", deobf)
        self.assertIn("'outer'", deobf)

    def test_get_variable_value_inlining(self):
        code = "$var = 'iex'; (Get-Variable var).Value"
        deobf = PowerShellDeobfuscator().deobfuscate(code)
        self.assertIn("'iex'", deobf)

    def test_dead_variable_elimination(self):
        code = """
        $dead1 = 'never_read'
        $live = 'read_me'
        $use = $live
        """
        # With eliminate_dead_vars=True, $dead1 is removed
        inliner = PowerShellVariableScopeInliner(eliminate_dead_vars=True)
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        norm_ast = inliner.inline(ast)
        source = PowerShellNormalizer().to_source(norm_ast)
        self.assertNotIn("never_read", source)
        self.assertIn("read_me", source)

    def test_dead_variable_elimination_preserves_side_effects(self):
        code = """
        $res = [System.IO.File]::Delete('target.tmp')
        """
        # Even if $res is never read, MethodCall has side effects so must NOT be dropped!
        inliner = PowerShellVariableScopeInliner(eliminate_dead_vars=True)
        tokens = PowerShellLexer(code).tokenize()
        ast = PowerShellParser(tokens).parse()
        norm_ast = inliner.inline(ast)
        source = PowerShellNormalizer().to_source(norm_ast)
        self.assertIn("Delete", source)


class TestVariableScopeTelemetryAndReports(unittest.TestCase):
    """Tests summary reports, JSON export, and deobfuscator engine methods."""

    def test_scope_analysis_report_format(self):
        script = "$x = 10; $y = $x + 5"
        summary = analyze_scopes(script)
        report = to_scope_report(summary)
        self.assertIn("PowerShell Variable Scope & Lifecycle Analysis", report)
        self.assertIn("Total Scopes:", report)
        self.assertIn("Total Symbols:", report)
        self.assertIn("$x @ script", report)

    def test_export_scope_json(self):
        script = "$a = 'alpha'; $b = $a"
        summary = analyze_scopes(script)
        json_str = export_scope_json(summary)
        data = json.loads(json_str)
        self.assertIn("telemetry", data)
        self.assertIn("scopes", data)
        self.assertIn("symbols", data)
        self.assertGreaterEqual(data["telemetry"]["total_symbols"], 2)

    def test_deobfuscator_engine_scope_analysis_method(self):
        engine = PowerShellDeobfuscator()
        script = "$key = 0xAA; $data = $key"
        summary = engine.get_scope_analysis(script)
        self.assertIsNotNone(summary)
        self.assertGreater(summary.total_symbols, 0)
        # After deobfuscate, last_scope_summary is populated
        _ = engine.deobfuscate(script)
        self.assertIsNotNone(engine.last_scope_summary)


class TestVariableScopeCLI(unittest.TestCase):
    """Tests CLI arguments: --scope-analysis, --scope-json, --export-scope-json, --eliminate-dead-vars."""

    def test_cli_scope_analysis_flag(self):
        cmd = [
            sys.executable,
            "-m",
            "src.cli",
            "$x = 'test'; $y = $x",
            "--scope-analysis",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(res.returncode, 0)
        self.assertIn("PowerShell Variable Scope & Lifecycle Analysis", res.stdout)
        self.assertIn("$x @ script", res.stdout)

    def test_cli_scope_json_flag(self):
        cmd = [
            sys.executable,
            "-m",
            "src.cli",
            "$token = 'secretToken'",
            "--scope-json",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertIn("telemetry", data)
        self.assertIn("symbols", data)

    def test_cli_export_scope_json_file(self):
        tmp_json = "temp_scope_test.json"
        try:
            cmd = [
                sys.executable,
                "-m",
                "src.cli",
                "$x = 1; $y = 2",
                "--export-scope-json",
                tmp_json,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(tmp_json))
            with open(tmp_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("telemetry", data)
        finally:
            if os.path.exists(tmp_json):
                os.remove(tmp_json)


if __name__ == "__main__":
    unittest.main()
