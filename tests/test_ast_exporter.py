"""
Unit and integration tests for PowerShell AST Exporter (Mermaid, DOT, JSON, Metrics).
"""

import json
import unittest

from src.ast_exporter import (
    ASTExporter,
    export_ast_dot,
    export_ast_json,
    export_ast_mermaid,
    extract_ast_metrics,
)
from src.ast_nodes import (
    CommandNode,
    IdentifierNode,
    IfStatementNode,
    NumberLiteralNode,
    PipelineNode,
    ScriptBlockNode,
    StringLiteralNode,
    VariableNode,
)
from src.lexer import PowerShellLexer
from src.parser import PowerShellParser


class TestASTExporter(unittest.TestCase):
    """Test suite for AST exporting to diagrams, JSON, and metrics."""

    def setUp(self):
        self.exporter = ASTExporter()

    def _parse(self, code: str) -> ScriptBlockNode:
        lexer = PowerShellLexer(code)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        return parser.parse()

    def test_mermaid_export_basic(self):
        code = "Get-Process -Name 'svchost'"
        ast = self._parse(code)
        mermaid = self.exporter.to_mermaid(ast, direction="TD")

        self.assertTrue(mermaid.startswith("flowchart TD"))
        self.assertIn("node_0", mermaid)
        self.assertIn("-->", mermaid)
        self.assertIn("Get-Process", mermaid)
        self.assertIn("svchost", mermaid)

    def test_mermaid_export_with_markdown_wrapper(self):
        code = "$x = 42"
        ast = self._parse(code)
        mermaid_md = self.exporter.to_mermaid(ast, wrap_markdown=True)

        self.assertTrue(mermaid_md.startswith("```mermaid\nflowchart TD"))
        self.assertTrue(mermaid_md.endswith("\n```"))

    def test_mermaid_shapes_and_control_flow(self):
        code = "if ($true) { Write-Host 'ok' }"
        ast = self._parse(code)
        mermaid = self.exporter.to_mermaid(ast)

        # Diamonds are used for IfStatementNode
        self.assertIn("{", mermaid)
        self.assertIn("}", mermaid)
        self.assertIn("IfStatement", mermaid)

    def test_mermaid_special_char_escaping(self):
        ast = ScriptBlockNode(
            statements=[
                StringLiteralNode(value='Test "quotes" & <tags> [brackets] (parens)')
            ]
        )
        mermaid = self.exporter.to_mermaid(ast)
        self.assertIn("#quot;", mermaid)
        self.assertIn("&amp;", mermaid)
        self.assertIn("&lt;", mermaid)
        self.assertIn("&gt;", mermaid)

    def test_dot_export_structure(self):
        code = "$var = 1 + 2"
        ast = self._parse(code)
        dot = self.exporter.to_dot(ast, graph_name="TestAST")

        self.assertTrue(dot.startswith("digraph TestAST {"))
        self.assertTrue(dot.endswith("}"))
        self.assertIn('rankdir="TB";', dot)
        self.assertIn("node_0", dot)
        self.assertIn("->", dot)
        self.assertIn("BinaryOp: +", dot)

    def test_json_export_structure(self):
        code = "Get-Service -Name 'wuauserv' | Out-Null"
        ast = self._parse(code)
        json_str = self.exporter.to_json(ast, indent=2)

        data = json.loads(json_str)
        self.assertEqual(data["type"], "ScriptBlockNode")
        self.assertIn("children", data)

        # Verify child structure
        stmt = data["children"][0]["node"]
        self.assertEqual(stmt["type"], "PipelineNode")

    def test_extract_metrics(self):
        code = """
        if ($true) {
            $x = 10
            Get-Process | Out-String
        } else {
            $y = 20
        }
        """
        ast = self._parse(code)
        metrics = self.exporter.extract_metrics(ast)

        self.assertGreater(metrics["total_nodes"], 5)
        self.assertGreater(metrics["max_depth"], 2)
        self.assertEqual(metrics["conditional_count"], 1)
        self.assertGreaterEqual(metrics["pipeline_count"], 1)
        self.assertIn("ScriptBlockNode", metrics["node_type_counts"])
        self.assertIn("IfStatementNode", metrics["node_type_counts"])
        self.assertGreaterEqual(metrics["cyclomatic_complexity"], 2)

    def test_convenience_functions(self):
        code = "$env:PATH.Substring(0, 10)"

        mermaid = export_ast_mermaid(code)
        self.assertTrue(mermaid.startswith("flowchart TD"))

        dot = export_ast_dot(code)
        self.assertTrue(dot.startswith("digraph PowerShellAST {"))

        json_out = export_ast_json(code)
        parsed = json.loads(json_out)
        self.assertEqual(parsed["type"], "ScriptBlockNode")

        metrics = extract_ast_metrics(code)
        self.assertIn("total_nodes", metrics)

    def test_cli_tree_and_formats(self):
        import io
        import os
        import tempfile
        from unittest.mock import patch
        from src.cli import main

        # Test --ast tree output
        with patch("sys.argv", ["powershell-ast-deobfuscator", "--ast", "Get-Process"]), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_out:
            main()
            output = mock_out.getvalue()
            self.assertIn("ScriptBlock", output)
            self.assertIn("Get-Process", output)

        # Test --mermaid
        with patch("sys.argv", ["powershell-ast-deobfuscator", "--mermaid", "Get-Process"]), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_out:
            main()
            output = mock_out.getvalue()
            self.assertIn("flowchart TD", output)

        # Test --json
        with patch("sys.argv", ["powershell-ast-deobfuscator", "--json", "Get-Process"]), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_out:
            main()
            output = mock_out.getvalue()
            parsed = json.loads(output)
            self.assertEqual(parsed["type"], "ScriptBlockNode")

        # Test --dot
        with patch("sys.argv", ["powershell-ast-deobfuscator", "--dot", "Get-Process"]), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_out:
            main()
            output = mock_out.getvalue()
            self.assertIn("digraph", output)

        # Test --stats
        with patch("sys.argv", ["powershell-ast-deobfuscator", "--stats", "Get-Process"]), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_out:
            main()
            output = mock_out.getvalue()
            stats = json.loads(output)
            self.assertIn("total_nodes", stats)

        # Test -o / --output file writing
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            tmp_path = tmp.name

        try:
            with patch(
                "sys.argv",
                ["powershell-ast-deobfuscator", "--json", "Get-Process", "-o", tmp_path],
            ), patch("sys.stdout", new_callable=io.StringIO):
                main()
            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()
            parsed = json.loads(content)
            self.assertEqual(parsed["type"], "ScriptBlockNode")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
