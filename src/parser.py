"""
PowerShell Recursive Descent AST Parser.
Parses token stream into hierarchical AST nodes.
"""

from typing import List, Optional

from .ast_nodes import (
    ASTNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    FormatOpNode,
    IdentifierNode,
    NumberLiteralNode,
    ParenthesizedExpressionNode,
    PipelineNode,
    ScriptBlockNode,
    StringLiteralNode,
    VariableNode,
)
from .tokens import Token, TokenType


class PowerShellParser:
    """
    Recursive descent parser for PowerShell syntax.
    """

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0

    def current(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]

    def peek(self, offset: int = 1) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return self.tokens[-1]

    def advance(self) -> Token:
        tok = self.current()
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return tok

    def match(self, *types: TokenType) -> bool:
        if self.current().type in types:
            self.advance()
            return True
        return False

    def expect(self, tok_type: TokenType) -> Token:
        tok = self.current()
        if tok.type != tok_type:
            raise SyntaxError(f"Expected {tok_type.name}, got {tok.type.name} ({tok.value!r}) at L{tok.line}:C{tok.column}")
        return self.advance()

    def parse(self) -> ScriptBlockNode:
        statements: List[ASTNode] = []
        while self.current().type != TokenType.EOF:
            # Skip empty newlines / semicolons
            if self.current().type in (TokenType.NEWLINE, TokenType.SEMICOLON):
                self.advance()
                continue
            stmt = self.parse_statement()
            if stmt:
                statements.append(stmt)
        return ScriptBlockNode(statements=statements)

    def parse_statement(self) -> Optional[ASTNode]:
        # Check variable assignment: $var = expr
        if self.current().type == TokenType.VARIABLE and self.peek().type == TokenType.OP_ASSIGN:
            var_tok = self.advance()
            self.advance()  # Skip '='
            expr = self.parse_expression()
            return AssignmentNode(
                variable=VariableNode(name=var_tok.value),
                expression=expr,
            )

        # Parse pipeline
        return self.parse_pipeline()

    def parse_pipeline(self) -> ASTNode:
        elements = [self.parse_command_or_expression()]
        while self.match(TokenType.OP_PIPE):
            elements.append(self.parse_command_or_expression())

        if len(elements) == 1:
            return elements[0]
        return PipelineNode(elements=elements)

    def parse_command_or_expression(self) -> ASTNode:
        expr = self.parse_expression()

        # If it's an identifier or command target, parse subsequent arguments
        if isinstance(expr, (IdentifierNode, StringLiteralNode)):
            args = []
            while self.current().type not in (
                TokenType.OP_PIPE,
                TokenType.SEMICOLON,
                TokenType.NEWLINE,
                TokenType.EOF,
                TokenType.RPAREN,
                TokenType.RBRACE,
            ):
                arg = self.parse_expression()
                if arg:
                    args.append(arg)
                else:
                    break
            if args:
                return CommandNode(target=expr, arguments=args)

        return expr

    def parse_expression(self) -> ASTNode:
        return self.parse_format_expression()

    def parse_format_expression(self) -> ASTNode:
        left = self.parse_binary_expression()

        # Check for '-f' operator: left -f arg0, arg1, ...
        if self.match(TokenType.OP_FORMAT):
            args = [self.parse_binary_expression()]
            while self.match(TokenType.COMMA):
                args.append(self.parse_binary_expression())
            return FormatOpNode(format_string=left, arguments=args)

        return left

    def parse_binary_expression(self) -> ASTNode:
        left = self.parse_primary()

        while self.current().type == TokenType.OP_PLUS:
            op_tok = self.advance()
            right = self.parse_primary()
            left = BinaryOpNode(left=left, operator=op_tok.value, right=right)

        return left

    def parse_primary(self) -> ASTNode:
        tok = self.current()

        # Parentheses
        if self.match(TokenType.LPAREN):
            inner = self.parse_expression()
            self.expect(TokenType.RPAREN)
            return ParenthesizedExpressionNode(expression=inner)

        # String literals
        if tok.type == TokenType.STRING_LITERAL:
            self.advance()
            is_expandable = tok.raw is not None and tok.raw.startswith('"')
            return StringLiteralNode(value=tok.value, is_expandable=is_expandable)

        # Numbers
        if tok.type == TokenType.NUMBER_LITERAL:
            self.advance()
            try:
                num = int(tok.value)
            except ValueError:
                num = float(tok.value)
            return NumberLiteralNode(value=num, raw=tok.value)

        # Variables
        if tok.type == TokenType.VARIABLE:
            self.advance()
            scope = None
            name = tok.value
            if ":" in name:
                parts = name.split(":", 1)
                scope = parts[0]
                name = parts[1]
            return VariableNode(name=name, scope=scope)

        # Identifiers
        if tok.type == TokenType.IDENTIFIER:
            self.advance()
            return IdentifierNode(name=tok.value)

        # Backtick standalone
        if tok.type == TokenType.BACKTICK_ESCAPE:
            self.advance()
            return StringLiteralNode(value=tok.value)

        # Fallback
        self.advance()
        return IdentifierNode(name=tok.value)
