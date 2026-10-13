"""
PowerShell Recursive Descent AST Parser.
Parses token stream into hierarchical AST nodes.
"""

from typing import List, Optional

from .ast_nodes import (
    ASTNode,
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
    SubexpressionNode,
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
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

    def _has_pipe_ahead(self) -> bool:
        idx = self.pos
        while idx < len(self.tokens):
            t = self.tokens[idx].type
            if t == TokenType.OP_PIPE:
                return True
            if t in (TokenType.SEMICOLON, TokenType.NEWLINE, TokenType.EOF, TokenType.RPAREN, TokenType.RBRACE):
                return False
            idx += 1
        return False

    def parse_statement(self) -> Optional[ASTNode]:
        # Check variable assignment: $var = pipeline_or_expr
        if self.current().type == TokenType.VARIABLE and self.peek().type == TokenType.OP_ASSIGN:
            var_tok = self.advance()
            self.advance()  # Skip '='
            expr = self.parse_pipeline()
            scope = None
            name = var_tok.value
            if ":" in name:
                parts = name.split(":", 1)
                scope = parts[0]
                name = parts[1]
            return AssignmentNode(
                variable=VariableNode(name=name, scope=scope),
                expression=expr,
            )

        # Check if statement: if (cond) { ... } [else { ... }]
        if self.current().type == TokenType.IDENTIFIER and self.current().value.lower() == "if":
            self.advance()  # Skip 'if'
            self.expect(TokenType.LPAREN)
            cond = self.parse_pipeline()
            self.expect(TokenType.RPAREN)
            if self.current().type == TokenType.LBRACE:
                then_block = self.parse_primary()
            else:
                then_stmt = self.parse_statement()
                then_block = ScriptBlockNode(statements=[then_stmt] if then_stmt else [], is_nested=True)
            else_block = None
            if self.current().type == TokenType.IDENTIFIER and self.current().value.lower() == "else":
                self.advance()  # Skip 'else'
                if self.current().type == TokenType.LBRACE:
                    else_block = self.parse_primary()
                else:
                    else_stmt = self.parse_statement()
                    else_block = ScriptBlockNode(statements=[else_stmt] if else_stmt else [], is_nested=True)
            return IfStatementNode(condition=cond, then_branch=then_block, else_branch=else_block)

        # Check while loop: while (cond) { ... }
        if self.current().type == TokenType.IDENTIFIER and self.current().value.lower() == "while":
            self.advance()  # Skip 'while'
            self.expect(TokenType.LPAREN)
            cond = self.parse_pipeline()
            self.expect(TokenType.RPAREN)
            if self.current().type == TokenType.LBRACE:
                body = self.parse_primary()
            else:
                stmt = self.parse_statement()
                body = ScriptBlockNode(statements=[stmt] if stmt else [], is_nested=True)
            return WhileStatementNode(condition=cond, body=body)

        # Parse pipeline
        return self.parse_pipeline()

    def parse_pipeline(self) -> ASTNode:
        first = self.parse_command_or_expression()
        if self.current().type == TokenType.COMMA and self._has_pipe_ahead():
            items = [first]
            while self.match(TokenType.COMMA):
                items.append(self.parse_command_or_expression())
            first = ArrayLiteralNode(elements=items)

        elements = [first]
        while self.match(TokenType.OP_PIPE):
            elem = self.parse_command_or_expression()
            if self.current().type == TokenType.COMMA and self._has_pipe_ahead():
                items = [elem]
                while self.match(TokenType.COMMA):
                    items.append(self.parse_command_or_expression())
                elem = ArrayLiteralNode(elements=items)
            elements.append(elem)

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
                TokenType.COMMA,
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
        return self.parse_format_or_join_expression()

    def parse_format_or_join_expression(self) -> ASTNode:
        left = self.parse_range_expression()

        # Check for '-f' operator: left -f arg0, arg1, ...
        if self.match(TokenType.OP_FORMAT):
            args = [self.parse_range_expression()]
            while self.match(TokenType.COMMA):
                args.append(self.parse_range_expression())
            return FormatOpNode(format_string=left, arguments=args)

        # Check for binary '-join' operator: left -join right
        if self.match(TokenType.OP_JOIN):
            right = self.parse_range_expression()
            return BinaryOpNode(left=left, operator="-join", right=right)

        return left

    def parse_range_expression(self) -> ASTNode:
        left = self.parse_binary_expression()

        if self.match(TokenType.OP_RANGE):
            right = self.parse_binary_expression()
            return RangeExpressionNode(start=left, end=right)

        return left

    def parse_binary_expression(self) -> ASTNode:
        left = self.parse_unary_expression()

        while True:
            if self.current().type in (TokenType.OP_PLUS, TokenType.OP_JOIN):
                op_tok = self.advance()
                right = self.parse_unary_expression()
                left = BinaryOpNode(left=left, operator=op_tok.value, right=right)
            elif self.current().type == TokenType.IDENTIFIER and self.current().value.lower() in (
                "-bxor", "-band", "-bor", "-shl", "-shr",
                "-eq", "-ne", "-gt", "-ge", "-lt", "-le",
                "-like", "-notlike", "-match", "-notmatch",
            ):
                op_tok = self.advance()
                right = self.parse_unary_expression()
                left = BinaryOpNode(left=left, operator=op_tok.value.lower(), right=right)
            else:
                break

        return left

    def parse_unary_expression(self) -> ASTNode:
        if self.match(TokenType.OP_JOIN):
            operand = self.parse_unary_expression()
            return UnaryOpNode(operator="-join", operand=operand)
        if self.current().type == TokenType.IDENTIFIER and self.current().value.lower() in ("-not", "!"):
            op_tok = self.advance()
            operand = self.parse_unary_expression()
            return UnaryOpNode(operator=op_tok.value.lower(), operand=operand)
        return self.parse_postfix_expression()

    def parse_postfix_expression(self) -> ASTNode:
        node = self.parse_primary()

        while True:
            # Member access: node.Member or node.Method(args) or dynamic node.(expr)
            if self.match(TokenType.OP_DOT):
                if self.current().type in (TokenType.IDENTIFIER, TokenType.STRING_LITERAL):
                    member_tok = self.advance()
                    member_name = member_tok.value
                    if self.match(TokenType.LPAREN):
                        args = []
                        if self.current().type != TokenType.RPAREN:
                            args.append(self.parse_expression())
                            while self.match(TokenType.COMMA):
                                args.append(self.parse_expression())
                        self.expect(TokenType.RPAREN)
                        node = MethodCallNode(target=node, method_name=member_name, arguments=args)
                    else:
                        node = MemberAccessNode(target=node, member=member_name)
                    continue
                elif self.current().type == TokenType.LPAREN:
                    member_expr = self.parse_primary()
                    if self.match(TokenType.LPAREN):
                        args = []
                        if self.current().type != TokenType.RPAREN:
                            args.append(self.parse_expression())
                            while self.match(TokenType.COMMA):
                                args.append(self.parse_expression())
                        self.expect(TokenType.RPAREN)
                        node = DynamicMethodCallNode(target=node, method_expr=member_expr, arguments=args)
                    else:
                        node = DynamicMemberAccessNode(target=node, member_expr=member_expr)
                    continue

            # Static member access: [Type]::Member or [Type]::Method(args) or dynamic [Type]::(expr)
            if self.match(TokenType.OP_COLON_COLON):
                type_name = getattr(node, "name", str(node)).strip("[]")
                if self.current().type in (TokenType.IDENTIFIER, TokenType.STRING_LITERAL):
                    member_tok = self.advance()
                    member_name = member_tok.value
                    if self.match(TokenType.LPAREN):
                        args = []
                        if self.current().type != TokenType.RPAREN:
                            args.append(self.parse_expression())
                            while self.match(TokenType.COMMA):
                                args.append(self.parse_expression())
                        self.expect(TokenType.RPAREN)
                        node = StaticMemberAccessNode(type_name=type_name, member=member_name, arguments=args)
                    else:
                        node = StaticMemberAccessNode(type_name=type_name, member=member_name, arguments=None)
                    continue
                elif self.current().type == TokenType.LPAREN:
                    member_expr = self.parse_primary()
                    if self.match(TokenType.LPAREN):
                        args = []
                        if self.current().type != TokenType.RPAREN:
                            args.append(self.parse_expression())
                            while self.match(TokenType.COMMA):
                                args.append(self.parse_expression())
                        self.expect(TokenType.RPAREN)
                        node = DynamicStaticMemberAccessNode(type_name=type_name, member_expr=member_expr, arguments=args)
                    else:
                        node = DynamicStaticMemberAccessNode(type_name=type_name, member_expr=member_expr, arguments=None)
                    continue

            # Index access: node[idx] or node[i0, i1, ...] or node[start..end]
            if self.match(TokenType.LBRACKET):
                idx = self.parse_format_or_join_expression()
                if self.match(TokenType.COMMA):
                    elements = [idx, self.parse_format_or_join_expression()]
                    while self.match(TokenType.COMMA):
                        elements.append(self.parse_format_or_join_expression())
                    self.expect(TokenType.RBRACKET)
                    idx_node = ArrayLiteralNode(elements=elements)
                else:
                    self.expect(TokenType.RBRACKET)
                    idx_node = idx
                node = IndexAccessNode(target=node, index=idx_node)
                continue

            break

        return node

    def parse_primary(self) -> ASTNode:
        tok = self.current()

        # Parentheses or comma-separated array: (1, 2) or (expr) or (cmd ...)
        if self.match(TokenType.LPAREN):
            first = self.parse_pipeline()
            if self.match(TokenType.COMMA):
                elements = [first, self.parse_pipeline()]
                while self.match(TokenType.COMMA):
                    elements.append(self.parse_pipeline())
                self.expect(TokenType.RPAREN)
                return ArrayLiteralNode(elements=elements)
            self.expect(TokenType.RPAREN)
            return ParenthesizedExpressionNode(expression=first)

        # Subexpression: $(stmt1; stmt2; ...)
        if self.match(TokenType.DOLLAR_LPAREN):
            statements = []
            while self.current().type not in (TokenType.RPAREN, TokenType.EOF):
                if self.current().type in (TokenType.NEWLINE, TokenType.SEMICOLON):
                    self.advance()
                    continue
                stmt = self.parse_statement()
                if stmt:
                    if self.match(TokenType.COMMA):
                        elements = [stmt]
                        next_stmt = self.parse_statement()
                        if next_stmt:
                            elements.append(next_stmt)
                        while self.match(TokenType.COMMA):
                            next_stmt = self.parse_statement()
                            if next_stmt:
                                elements.append(next_stmt)
                        stmt = ArrayLiteralNode(elements=elements)
                    statements.append(stmt)
            self.expect(TokenType.RPAREN)
            return SubexpressionNode(statements=statements)

        # Array subexpression: @(item0, item1, ...)
        if self.match(TokenType.AT):
            if self.match(TokenType.LPAREN):
                elements = []
                if self.current().type != TokenType.RPAREN:
                    elements.append(self.parse_pipeline())
                    while self.match(TokenType.COMMA):
                        elements.append(self.parse_pipeline())
                self.expect(TokenType.RPAREN)
                return ArrayLiteralNode(elements=elements)
            return IdentifierNode(name="@")

        # ScriptBlock literal: { ... }
        if self.match(TokenType.LBRACE):
            statements = []
            while self.current().type not in (TokenType.RBRACE, TokenType.EOF):
                if self.current().type in (TokenType.NEWLINE, TokenType.SEMICOLON):
                    self.advance()
                    continue
                stmt = self.parse_statement()
                if stmt:
                    statements.append(stmt)
            self.expect(TokenType.RBRACE)
            return ScriptBlockNode(statements=statements, is_nested=True)

        # Type literal or type cast: [Type] or [byte[]](...)
        if self.match(TokenType.LBRACKET):
            type_tokens = []
            bracket_depth = 1
            while bracket_depth > 0 and self.current().type != TokenType.EOF:
                if self.current().type == TokenType.LBRACKET:
                    bracket_depth += 1
                    type_tokens.append(self.advance().value)
                elif self.current().type == TokenType.RBRACKET:
                    bracket_depth -= 1
                    if bracket_depth == 0:
                        self.advance()  # consume outer closing ']'
                        break
                    else:
                        type_tokens.append(self.advance().value)
                else:
                    type_tokens.append(self.advance().value)
            type_name = "".join(type_tokens)

            # If followed by '::', it's a static type target
            if self.current().type == TokenType.OP_COLON_COLON:
                return IdentifierNode(name=type_name)

            # If followed by an expression, it's a type cast: [byte[]](1..16), [char]65, [string][char[]](...)
            if self.current().type in (
                TokenType.LPAREN,
                TokenType.DOLLAR_LPAREN,
                TokenType.VARIABLE,
                TokenType.AT,
                TokenType.NUMBER_LITERAL,
                TokenType.STRING_LITERAL,
                TokenType.LBRACKET,
                TokenType.IDENTIFIER,
            ):
                target_expr = self.parse_postfix_expression()
                return TypeCastNode(type_name=type_name, expression=target_expr)

            return IdentifierNode(name=f"[{type_name}]")

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

