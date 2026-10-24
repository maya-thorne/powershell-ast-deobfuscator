"""
Comprehensive unit and integration tests for PowerShell 7+ (Core / pwsh) AST extensions:
- Null-coalescing operator (??)
- Null-coalescing assignment operator (??=)
- Ternary operator (?:)
- Semantic truthiness and nullness evaluation
- Dead code elimination and constant folding
- AST visualizer and diagram exporter integration
- Multi-pass fixed-point deobfuscation engine integration
"""

import unittest

from src.ast_exporter import ASTExporter
from src.ast_nodes import (
    ArrayLiteralNode,
    BinaryOpNode,
    CoalesceAssignmentNode,
    CoalesceExpressionNode,
    CommandNode,
    FormatOpNode,
    IdentifierNode,
    NumberLiteralNode,
    PipelineNode,
    ScriptBlockNode,
    StringLiteralNode,
    TernaryExpressionNode,
    VariableNode,
)
from src.ast_visualizer import ASTVisualizer
from src.deobfuscator_engine import PowerShellDeobfuscator
from src.lexer import PowerShellLexer
from src.normalizer import PowerShellNormalizer
from src.parser import PowerShellParser
from src.pwsh7 import (
    PowerShell7Reducer,
    fold_pwsh7_operators,
    is_statically_null,
    is_statically_truthy,
)
from src.tokens import TokenType


class TestPowerShell7Lexer(unittest.TestCase):
    """Verifies lexical scanning of PowerShell 7+ operator tokens."""

    def test_lex_null_coalescing(self):
        code = "$a ?? $b"
        tokens = PowerShellLexer(code).tokenize()
        types = [t.type for t in tokens if t.type != TokenType.EOF]
        self.assertEqual(types, [TokenType.VARIABLE, TokenType.OP_COALESCE, TokenType.VARIABLE])
        self.assertEqual(tokens[1].value, "??")

    def test_lex_null_coalescing_assignment(self):
        code = "$x ??= 'default'"
        tokens = PowerShellLexer(code).tokenize()
        types = [t.type for t in tokens if t.type != TokenType.EOF]
        self.assertEqual(types, [TokenType.VARIABLE, TokenType.OP_COALESCE_ASSIGN, TokenType.STRING_LITERAL])
        self.assertEqual(tokens[1].value, "??=")

    def test_lex_ternary_operator(self):
        code = "$cond ? 'yes' : 'no'"
        tokens = PowerShellLexer(code).tokenize()
        types = [t.type for t in tokens if t.type != TokenType.EOF]
        self.assertEqual(
            types,
            [
                TokenType.VARIABLE,
                TokenType.OP_QUESTION,
                TokenType.STRING_LITERAL,
                TokenType.OP_COLON,
                TokenType.STRING_LITERAL,
            ],
        )

    def test_lex_colon_disambiguation(self):
        # Single colon for ternary, double colon for static members
        code = "$is_admin ? [System.Math]::Max(1, 2) : 0"
        tokens = PowerShellLexer(code).tokenize()
        colon_types = [t.type for t in tokens if t.type in (TokenType.OP_COLON, TokenType.OP_COLON_COLON)]
        self.assertEqual(colon_types, [TokenType.OP_COLON_COLON, TokenType.OP_COLON])


class TestPowerShell7Parser(unittest.TestCase):
    """Verifies recursive descent parsing of PowerShell 7+ syntax trees."""

    def test_parse_simple_coalesce(self):
        code = "$val ?? 'fallback'"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        self.assertEqual(len(ast.statements), 1)
        node = ast.statements[0]
        self.assertIsInstance(node, CoalesceExpressionNode)
        self.assertIsInstance(node.left, VariableNode)
        self.assertEqual(node.left.name, "val")
        self.assertIsInstance(node.right, StringLiteralNode)
        self.assertEqual(node.right.value, "fallback")

    def test_parse_chained_coalesce_right_associative(self):
        code = "$a ?? $b ?? 'default'"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        node = ast.statements[0]
        self.assertIsInstance(node, CoalesceExpressionNode)
        self.assertIsInstance(node.left, VariableNode)
        self.assertEqual(node.left.name, "a")
        self.assertIsInstance(node.right, CoalesceExpressionNode)
        self.assertEqual(node.right.left.name, "b")
        self.assertEqual(node.right.right.value, "default")

    def test_parse_coalesce_assignment(self):
        code = "$cache ??= 42"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        node = ast.statements[0]
        self.assertIsInstance(node, CoalesceAssignmentNode)
        self.assertEqual(node.variable.name, "cache")
        self.assertEqual(node.expression.value, 42)

    def test_parse_simple_ternary(self):
        code = "$isEnabled ? 'Active' : 'Disabled'"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        node = ast.statements[0]
        self.assertIsInstance(node, TernaryExpressionNode)
        self.assertEqual(node.condition.name, "isEnabled")
        self.assertEqual(node.if_true.value, "Active")
        self.assertEqual(node.if_false.value, "Disabled")

    def test_parse_parenthesized_condition(self):
        code = "($score -gt 50) ? 'Pass' : 'Fail'"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        node = ast.statements[0]
        self.assertIsInstance(node, TernaryExpressionNode)
        self.assertEqual(node.if_true.value, "Pass")
        self.assertEqual(node.if_false.value, "Fail")

    def test_parse_nested_ternary_right_associative(self):
        code = "$a ? 1 : $b ? 2 : 3"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        node = ast.statements[0]
        self.assertIsInstance(node, TernaryExpressionNode)
        self.assertEqual(node.condition.name, "a")
        self.assertEqual(node.if_true.value, 1)
        self.assertIsInstance(node.if_false, TernaryExpressionNode)
        self.assertEqual(node.if_false.condition.name, "b")
        self.assertEqual(node.if_false.if_true.value, 2)
        self.assertEqual(node.if_false.if_false.value, 3)

    def test_parse_operator_precedence_coalesce_over_ternary(self):
        # ?? binds tighter than ?: -> ($a ?? $b) ? $c : $d
        code = "$a ?? $b ? 'yes' : 'no'"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        node = ast.statements[0]
        self.assertIsInstance(node, TernaryExpressionNode)
        self.assertIsInstance(node.condition, CoalesceExpressionNode)
        self.assertEqual(node.condition.left.name, "a")
        self.assertEqual(node.condition.right.name, "b")

    def test_parse_where_object_pipeline_preserved(self):
        # Ensure '?' as Where-Object alias in a pipeline is not mistaken for a ternary operator
        code = "Get-Process | ? { $_.CPU -gt 10 }"
        ast = PowerShellParser(PowerShellLexer(code).tokenize()).parse()
        node = ast.statements[0]
        self.assertIsInstance(node, PipelineNode)
        self.assertEqual(len(node.elements), 2)
        cmd_stage = node.elements[1]
        self.assertIsInstance(cmd_stage, CommandNode)
        self.assertEqual(cmd_stage.target.name, "?")


class TestPowerShell7Normalizer(unittest.TestCase):
    """Verifies source reconstruction of PowerShell 7+ AST nodes."""

    def test_to_source_coalesce(self):
        norm = PowerShellNormalizer()
        node = CoalesceExpressionNode(left=VariableNode(name="x"), right=StringLiteralNode(value="default"))
        src = norm.to_source(node)
        self.assertEqual(src, "$x ?? 'default'")

    def test_to_source_coalesce_assignment(self):
        norm = PowerShellNormalizer()
        node = CoalesceAssignmentNode(variable=VariableNode(name="opt"), expression=NumberLiteralNode(value=100, raw="100"))
        src = norm.to_source(node)
        self.assertEqual(src, "$opt ??= 100")

    def test_to_source_ternary(self):
        norm = PowerShellNormalizer()
        node = TernaryExpressionNode(
            condition=VariableNode(name="flag"),
            if_true=StringLiteralNode(value="ON"),
            if_false=StringLiteralNode(value="OFF"),
        )
        src = norm.to_source(node)
        self.assertEqual(src, "$flag ? 'ON' : 'OFF'")


class TestPowerShell7Reducer(unittest.TestCase):
    """Verifies static truthiness, nullness, dead code elimination, and constant folding."""

    def test_evaluate_truthiness_primitives(self):
        reducer = PowerShell7Reducer()
        self.assertTrue(reducer.evaluate_truthiness(VariableNode(name="true")))
        self.assertFalse(reducer.evaluate_truthiness(VariableNode(name="false")))
        self.assertFalse(reducer.evaluate_truthiness(VariableNode(name="null")))
        self.assertTrue(reducer.evaluate_truthiness(NumberLiteralNode(value=1, raw="1")))
        self.assertFalse(reducer.evaluate_truthiness(NumberLiteralNode(value=0, raw="0")))
        self.assertTrue(reducer.evaluate_truthiness(StringLiteralNode(value="content")))
        self.assertFalse(reducer.evaluate_truthiness(StringLiteralNode(value="")))
        self.assertTrue(reducer.evaluate_truthiness(ArrayLiteralNode(elements=[NumberLiteralNode(value=1, raw="1")])))
        self.assertFalse(reducer.evaluate_truthiness(ArrayLiteralNode(elements=[])))

    def test_evaluate_truthiness_comparisons(self):
        reducer = PowerShell7Reducer()
        # -eq
        eq_node = BinaryOpNode(left=NumberLiteralNode(value=5, raw="5"), operator="-eq", right=NumberLiteralNode(value=5, raw="5"))
        self.assertTrue(reducer.evaluate_truthiness(eq_node))

        # -gt
        gt_node = BinaryOpNode(left=NumberLiteralNode(value=2, raw="2"), operator="-gt", right=NumberLiteralNode(value=10, raw="10"))
        self.assertFalse(reducer.evaluate_truthiness(gt_node))

        # -like
        like_node = BinaryOpNode(left=StringLiteralNode(value="malware.ps1"), operator="-like", right=StringLiteralNode(value="*.ps1"))
        self.assertTrue(reducer.evaluate_truthiness(like_node))

        # -match
        match_node = BinaryOpNode(left=StringLiteralNode(value="powershell7"), operator="-match", right=StringLiteralNode(value=r"\d+"))
        self.assertTrue(reducer.evaluate_truthiness(match_node))

    def test_evaluate_nullness_primitives(self):
        reducer = PowerShell7Reducer(symbols={"existing": "data", "unset": None})
        self.assertTrue(reducer.evaluate_nullness(VariableNode(name="null")))
        self.assertTrue(reducer.evaluate_nullness(VariableNode(name="unset")))
        self.assertFalse(reducer.evaluate_nullness(VariableNode(name="existing")))
        self.assertFalse(reducer.evaluate_nullness(StringLiteralNode(value="text")))
        self.assertFalse(reducer.evaluate_nullness(NumberLiteralNode(value=0, raw="0")))

    def test_fold_ternary_truthy_branch_eliminates_false(self):
        reducer = PowerShell7Reducer()
        node = TernaryExpressionNode(
            condition=VariableNode(name="true"),
            if_true=StringLiteralNode(value="RETAINED_PAYLOAD"),
            if_false=StringLiteralNode(value="ELIMINATED_DECOY"),
        )
        folded = reducer.reduce(node)
        self.assertIsInstance(folded, StringLiteralNode)
        self.assertEqual(folded.value, "RETAINED_PAYLOAD")

    def test_fold_ternary_falsy_branch_eliminates_true(self):
        reducer = PowerShell7Reducer()
        node = TernaryExpressionNode(
            condition=NumberLiteralNode(value=0, raw="0"),
            if_true=StringLiteralNode(value="ELIMINATED_DECOY"),
            if_false=StringLiteralNode(value="RETAINED_PAYLOAD"),
        )
        folded = reducer.reduce(node)
        self.assertIsInstance(folded, StringLiteralNode)
        self.assertEqual(folded.value, "RETAINED_PAYLOAD")

    def test_fold_coalesce_left_null_folds_to_right(self):
        reducer = PowerShell7Reducer()
        node = CoalesceExpressionNode(
            left=VariableNode(name="null"),
            right=StringLiteralNode(value="DESIRED_VALUE"),
        )
        folded = reducer.reduce(node)
        self.assertIsInstance(folded, StringLiteralNode)
        self.assertEqual(folded.value, "DESIRED_VALUE")

    def test_fold_coalesce_left_non_null_folds_to_left(self):
        reducer = PowerShell7Reducer()
        node = CoalesceExpressionNode(
            left=StringLiteralNode(value="PRIMARY_VALUE"),
            right=StringLiteralNode(value="UNUSED_FALLBACK"),
        )
        folded = reducer.reduce(node)
        self.assertIsInstance(folded, StringLiteralNode)
        self.assertEqual(folded.value, "PRIMARY_VALUE")

    def test_fold_coalesce_assignment_no_op_when_bound(self):
        reducer = PowerShell7Reducer(symbols={"existing": "initial_data"})
        node = CoalesceAssignmentNode(
            variable=VariableNode(name="existing"),
            expression=StringLiteralNode(value="new_data"),
        )
        folded = reducer.reduce(node)
        # Should fold to no-op access $existing without overwriting
        self.assertIsInstance(folded, VariableNode)
        self.assertEqual(reducer.symbols["existing"], "initial_data")

    def test_fold_coalesce_assignment_assigns_when_unbound(self):
        reducer = PowerShell7Reducer()
        node = CoalesceAssignmentNode(
            variable=VariableNode(name="unbound_var"),
            expression=StringLiteralNode(value="assigned_value"),
        )
        folded = reducer.reduce(node)
        self.assertIsInstance(folded, CoalesceAssignmentNode)
        self.assertEqual(reducer.symbols.get("unbound_var"), "assigned_value")

    def test_public_facade_helpers(self):
        ast = PowerShellParser(PowerShellLexer("$true ? 'a' : 'b'").tokenize()).parse()
        folded = fold_pwsh7_operators(ast)
        self.assertIsInstance(folded.statements[0], StringLiteralNode)
        self.assertEqual(folded.statements[0].value, "a")

        self.assertTrue(is_statically_truthy(StringLiteralNode(value="ok")))
        self.assertFalse(is_statically_truthy(StringLiteralNode(value="")))
        self.assertTrue(is_statically_null(VariableNode(name="null")))
        self.assertFalse(is_statically_null(NumberLiteralNode(value=10, raw="10")))


class TestPowerShell7ASTVisualizerAndExporter(unittest.TestCase):
    """Verifies tree visualization and diagram export for PowerShell 7+ nodes."""

    def test_ast_visualizer_tree(self):
        viz = ASTVisualizer(unicode=False)
        node = TernaryExpressionNode(
            condition=VariableNode(name="is_admin"),
            if_true=StringLiteralNode(value="FullControl"),
            if_false=StringLiteralNode(value="ReadOnly"),
        )
        tree_text = viz.render(node)
        self.assertIn("TernaryExpression", tree_text)
        self.assertIn("FullControl", tree_text)
        self.assertIn("ReadOnly", tree_text)

    def test_mermaid_export_shape(self):
        exporter = ASTExporter()
        node = TernaryExpressionNode(
            condition=VariableNode(name="flag"),
            if_true=NumberLiteralNode(value=1, raw="1"),
            if_false=NumberLiteralNode(value=0, raw="0"),
        )
        mermaid = exporter.to_mermaid(node)
        self.assertIn("flowchart", mermaid)
        self.assertIn("{", mermaid)  # Diamond node shape for control flow


class TestPowerShell7EndToEndDeobfuscation(unittest.TestCase):
    """Verifies full multi-pass deobfuscation engine with real-world style obfuscated payloads."""

    def test_deobfuscate_opaque_predicate_ternary(self):
        deobfuscator = PowerShellDeobfuscator()
        script = """
        $target = (1 -eq 1) ? ('i' + 'ex') : 'exit'
        $val = ('alpha' -like '*pha') ? ('p' + 'w' + 'sh') : 'cmd'
        """
        result = deobfuscator.deobfuscate(script)
        self.assertIn("$target = 'iex'", result)
        self.assertIn("$val = 'pwsh'", result)
        self.assertNotIn("exit", result)
        self.assertNotIn("cmd", result)

    def test_deobfuscate_nested_coalesce_chain(self):
        deobfuscator = PowerShellDeobfuscator()
        script = "$cmd = $null ?? $null ?? ('calc' + '.exe')"
        result = deobfuscator.deobfuscate(script)
        self.assertEqual(result.strip(), "$cmd = 'calc.exe'")

    def test_deobfuscate_pwsh7_with_format_operator(self):
        deobfuscator = PowerShellDeobfuscator()
        script = "$run = $true ? ('{0}:{1}' -f 'https', '//c2.corp') : 'decoy'"
        result = deobfuscator.deobfuscate(script)
        self.assertIn("$run = 'https://c2.corp'", result)
        self.assertNotIn("decoy", result)


if __name__ == "__main__":
    unittest.main()
