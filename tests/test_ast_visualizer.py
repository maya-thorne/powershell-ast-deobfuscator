"""
Unit and integration tests for PowerShell AST Visualizer (Tree Renderer).
"""

import unittest

from src.ast_nodes import (
    ArrayLiteralNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    DynamicMemberAccessNode,
    DynamicMethodCallNode,
    DynamicStaticMemberAccessNode,
    FormatOpNode,
    IdentifierNode,
    IfStatementNode,
    IndexAccessNode,
    MemberAccessNode,
    MethodCallNode,
    NumberLiteralNode,
    ParenthesizedExpressionNode,
    PipelineNode,
    RangeExpressionNode,
    ScriptBlockNode,
    StaticMemberAccessNode,
    StringLiteralNode,
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from src.ast_visualizer import ASTVisualizer, render_ast_tree
from src.lexer import PowerShellLexer
from src.parser import PowerShellParser


class TestASTVisualizer(unittest.TestCase):
    """Test suite for AST visualizer and tree rendering."""

    def setUp(self):
        self.visualizer_unicode = ASTVisualizer(unicode=True)
        self.visualizer_ascii = ASTVisualizer(unicode=False)

    def _parse(self, code: str) -> ScriptBlockNode:
        lexer = PowerShellLexer(code)
        tokens = lexer.tokenize()
        parser = PowerShellParser(tokens)
        return parser.parse()

    def test_empty_script_block(self):
        ast = ScriptBlockNode()
        tree = self.visualizer_unicode.render(ast)
        self.assertIn("ScriptBlock (root, 0 statements)", tree)

    def test_simple_command_unicode_tree(self):
        code = "Get-Process -Name 'powershell'"
        tree = render_ast_tree(code, unicode=True)
        self.assertIn("ScriptBlock (root, 1 statement)", tree)
        self.assertIn("Command (2 args)", tree)
        self.assertIn("Identifier: 'Get-Process'", tree)
        self.assertIn("StringLiteral: 'powershell'", tree)
        self.assertIn("├── ", tree)
        self.assertIn("└── ", tree)

    def test_simple_command_ascii_tree(self):
        code = "Get-Process; Stop-Process"
        tree = render_ast_tree(code, unicode=False)
        self.assertIn("ScriptBlock (root, 2 statements)", tree)
        self.assertIn("|-- ", tree)
        self.assertIn("\\-- ", tree)
        self.assertNotIn("├──", tree)

    def test_pipeline_and_methods(self):
        code = "$x = 'hello'.Substring(0, 2)"
        tree = render_ast_tree(code, unicode=True)
        self.assertIn("Assignment: $x =", tree)
        self.assertIn("MethodCall: .Substring(2 args)", tree)
        self.assertIn("StringLiteral: 'hello'", tree)
        self.assertIn("NumberLiteral: 0", tree)

    def test_format_operator_and_binary_ops(self):
        code = "'{0}' -f (1 + 2)"
        tree = render_ast_tree(code, unicode=True)
        self.assertIn("FormatOp: -f (1 arg)", tree)
        self.assertIn("BinaryOp: +", tree)

    def test_static_members_and_type_casts(self):
        code = "[System.Convert]::ToInt32('42')"
        tree = render_ast_tree(code, unicode=True)
        self.assertIn("StaticMemberCall: [System.Convert]::ToInt32(1 args)", tree)
        self.assertIn("StringLiteral: '42'", tree)

    def test_index_access_and_ranges(self):
        code = "$arr[0..5]"
        tree = render_ast_tree(code, unicode=True)
        self.assertIn("IndexAccess: target[index]", tree)
        self.assertIn("RangeExpression: ..", tree)

    def test_conditionals_and_loops(self):
        code = "if ($true) { Get-Service } else { Get-Process }"
        tree = render_ast_tree(code, unicode=True)
        self.assertIn("IfStatement (with else)", tree)
        self.assertIn("[condition]", tree)
        self.assertIn("[then]", tree)
        self.assertIn("[else]", tree)
        self.assertIn("Get-Service", tree)
        self.assertIn("Get-Process", tree)

    def test_while_loop(self):
        code = "while ($true) { Write-Host 'loop' }"
        tree = render_ast_tree(code, unicode=True)
        self.assertIn("WhileStatement", tree)
        self.assertIn("[condition]", tree)
        self.assertIn("[body]", tree)

    def test_unary_and_array_literals(self):
        code = "-join @('a', 'b', 'c')"
        tree = render_ast_tree(code, unicode=True)
        self.assertIn("UnaryOp: -join", tree)
        self.assertIn("ArrayLiteral (3 elements)", tree)

    def test_dynamic_member_and_static_access(self):
        ast = ScriptBlockNode(
            statements=[
                DynamicMemberAccessNode(
                    target=VariableNode(name="obj"),
                    member_expr=StringLiteralNode(value="Length"),
                ),
                DynamicMethodCallNode(
                    target=VariableNode(name="obj"),
                    method_expr=StringLiteralNode(value="Substring"),
                    arguments=[NumberLiteralNode(value=0, raw="0")],
                ),
                DynamicStaticMemberAccessNode(
                    type_name="System.Math",
                    member_expr=StringLiteralNode(value="Abs"),
                    arguments=[NumberLiteralNode(value=-5, raw="-5")],
                ),
            ]
        )
        tree = self.visualizer_unicode.render(ast)
        self.assertIn("DynamicMemberAccess: target.(expr)", tree)
        self.assertIn("DynamicMethodCall: target.(expr)(1 args)", tree)
        self.assertIn("DynamicStaticMemberCall: [System.Math]::(expr)(1 args)", tree)

    def test_max_depth_guard(self):
        vis = ASTVisualizer(max_depth=2)
        code = "1 + 2 + 3 + 4 + 5"
        tree = vis.render(self._parse(code))
        self.assertIn("Max depth 2 reached", tree)

    def test_string_truncation(self):
        vis = ASTVisualizer(truncate_len=20)
        node = StringLiteralNode(value="This is a very long string that should be truncated cleanly")
        label = vis.get_node_label(node)
        self.assertIn("...", label)
        self.assertTrue(len(label) < 60)

    def test_edge_label_toggle(self):
        vis_no_edges = ASTVisualizer(show_edge_labels=False)
        code = "$x = 10"
        tree = vis_no_edges.render(self._parse(code))
        self.assertNotIn("[variable]", tree)
        self.assertNotIn("[expression]", tree)


if __name__ == "__main__":
    unittest.main()
