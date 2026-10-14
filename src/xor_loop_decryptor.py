"""
PowerShell Static XOR Decryption Loop Evaluator.
Statically analyzes and reverses XOR encryption loops and byte stream transforms
across pipeline ForEach-Object blocks, repeating-key ciphers, and imperative for/foreach/while loops.
"""

import base64
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .ast_nodes import (
    ASTNode,
    ArrayLiteralNode,
    AssignmentNode,
    BinaryOpNode,
    CommandNode,
    ForEachStatementNode,
    ForStatementNode,
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
from .secure_string_crypto import zeroize_buffer
from .type_accelerators import TypeAcceleratorRegistry

MAX_LOOP_ITERATIONS = 50000


class PowerShellXorLoopDecryptor:
    """
    Compiler-grade static evaluator for XOR decryption loops in PowerShell payloads.
    Resolves:
      1. Pipeline XOR loops: @(0x35, 0x21) | % { [char]($_ -bxor 0x55) }
      2. Multi-byte repeating key XOR: $bytes | % { $_ -bxor $k[$i++ % $k.Length] }
      3. Encoding wrappers: [System.Text.Encoding]::ASCII.GetString($bytes | % { $_ -bxor $key })
      4. Imperative for loops: for ($i=0; $i -lt $enc.Length; $i++) { $out += [char]($enc[$i] -bxor $k) }
      5. In-place byte array mutations: for ($i=0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor $k }
      6. Imperative foreach loops: foreach ($b in $enc) { $out += [char]($b -bxor $k) }
    """

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols: Dict[str, Any] = symbols if symbols is not None else {}

    def decrypt(self, node: ASTNode) -> ASTNode:
        """Traverses the AST and statically evaluates all detected XOR decryption loops."""
        return self._visit(node)

    def _visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            new_stmts: List[ASTNode] = []
            for s in node.statements:
                norm_s = self._visit(s)
                new_stmts.append(norm_s)
            return ScriptBlockNode(statements=new_stmts, is_nested=node.is_nested)

        if isinstance(node, AssignmentNode):
            norm_var: ASTNode
            if isinstance(node.variable, IndexAccessNode):
                norm_var = IndexAccessNode(
                    target=node.variable.target,
                    index=self._visit(node.variable.index),
                )
            else:
                norm_var = node.variable

            norm_expr = self._visit(node.expression)
            # Track symbol assignments
            if isinstance(norm_var, VariableNode):
                v_name = norm_var.name.lower()
                extracted = self._extract_bytes(norm_expr)
                if extracted is not None:
                    self.symbols[v_name] = extracted
                elif isinstance(norm_expr, NumberLiteralNode):
                    self.symbols[v_name] = norm_expr.value
                elif isinstance(norm_expr, StringLiteralNode):
                    self.symbols[v_name] = norm_expr.value
            return AssignmentNode(variable=norm_var, expression=norm_expr)

        if isinstance(node, ForStatementNode):
            decrypted = self._decrypt_for_loop(node)
            if decrypted is not None:
                return decrypted
            return ForStatementNode(
                initializer=self._visit(node.initializer) if node.initializer else None,
                condition=self._visit(node.condition) if node.condition else None,
                iterator=self._visit(node.iterator) if node.iterator else None,
                body=self._visit(node.body) if node.body else None,
            )

        if isinstance(node, ForEachStatementNode):
            decrypted = self._decrypt_foreach_loop(node)
            if decrypted is not None:
                return decrypted
            return ForEachStatementNode(
                variable=self._visit(node.variable) if node.variable else None,
                collection=self._visit(node.collection) if node.collection else None,
                body=self._visit(node.body) if node.body else None,
            )

        if isinstance(node, WhileStatementNode):
            decrypted = self._decrypt_while_loop(node)
            if decrypted is not None:
                return decrypted
            return WhileStatementNode(condition=self._visit(node.condition), body=self._visit(node.body))

        if isinstance(node, PipelineNode):
            decrypted_pipe = self._decrypt_pipeline(node)
            if decrypted_pipe is not None:
                return decrypted_pipe
            return PipelineNode(elements=[self._visit(e) for e in node.elements])

        if isinstance(node, StaticMemberAccessNode):
            # [System.Text.Encoding]::ASCII.GetString($bytes | % { $_ -bxor $k })
            decrypted_member = self._decrypt_static_encoding_call(node)
            if decrypted_member is not None:
                return decrypted_member
            norm_args = [self._visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)

        if isinstance(node, MethodCallNode):
            decrypted_call = self._decrypt_method_call(node)
            if decrypted_call is not None:
                return decrypted_call
            return MethodCallNode(
                target=self._visit(node.target),
                method_name=node.method_name,
                arguments=[self._visit(a) for a in node.arguments],
            )

        if isinstance(node, ParenthesizedExpressionNode):
            inner = self._visit(node.expression)
            # Check if parenthesized pipeline resolved to string
            if isinstance(inner, (StringLiteralNode, NumberLiteralNode)):
                return inner
            return ParenthesizedExpressionNode(expression=inner)

        if isinstance(node, BinaryOpNode):
            left = self._visit(node.left)
            right = self._visit(node.right)
            # Check ($pipeline) -join ''
            if node.operator.lower() == "-join":
                if isinstance(left, StringLiteralNode):
                    return left
                if isinstance(left, ParenthesizedExpressionNode) and isinstance(left.expression, StringLiteralNode):
                    return left.expression
                if isinstance(left, PipelineNode):
                    dec = self._decrypt_pipeline(left, force_join=True)
                    if dec is not None:
                        return dec
                elif isinstance(left, ParenthesizedExpressionNode) and isinstance(left.expression, PipelineNode):
                    dec = self._decrypt_pipeline(left.expression, force_join=True)
                    if dec is not None:
                        return dec
            return BinaryOpNode(left=left, operator=node.operator, right=right)

        if isinstance(node, UnaryOpNode):
            operand = self._visit(node.operand)
            # Check -join ($pipeline)
            if node.operator.lower() == "-join":
                if isinstance(operand, StringLiteralNode):
                    return operand
                if isinstance(operand, ParenthesizedExpressionNode) and isinstance(operand.expression, StringLiteralNode):
                    return operand.expression
                if isinstance(operand, PipelineNode):
                    dec = self._decrypt_pipeline(operand, force_join=True)
                    if dec is not None:
                        return dec
                elif isinstance(operand, ParenthesizedExpressionNode) and isinstance(operand.expression, PipelineNode):
                    dec = self._decrypt_pipeline(operand.expression, force_join=True)
                    if dec is not None:
                        return dec
            return UnaryOpNode(operator=node.operator, operand=operand)

        if isinstance(node, IfStatementNode):
            return IfStatementNode(
                condition=self._visit(node.condition),
                then_branch=self._visit(node.then_branch),
                else_branch=self._visit(node.else_branch) if node.else_branch else None,
            )

        if isinstance(node, SubexpressionNode):
            return SubexpressionNode(statements=[self._visit(s) for s in node.statements])

        if isinstance(node, CommandNode):
            return CommandNode(target=self._visit(node.target), arguments=[self._visit(a) for a in node.arguments])

        return node

    def _decrypt_pipeline(self, node: PipelineNode, force_join: bool = False) -> Optional[ASTNode]:
        """Evaluates pipeline XOR stages: collection | % { [char]($_ -bxor $key) }."""
        if len(node.elements) < 2:
            return None

        source = node.elements[0]
        stage = node.elements[1]

        # Check if stage 1 is ForEach-Object / %
        if not self._is_foreach_stage(stage):
            return None

        # Extract data bytes from source
        data = self._extract_bytes(source)
        if data is None or len(data) == 0 or len(data) > MAX_LOOP_ITERATIONS:
            return None

        script_block = self._get_script_block_from_stage(stage)
        if script_block is None or not script_block.statements:
            return None

        body_stmt = script_block.statements[0]

        # Analyze XOR operation inside Foreach block
        xor_info = self._analyze_xor_body(body_stmt)
        if xor_info is None:
            return None

        key_bytes, converts_to_char = xor_info
        if not key_bytes:
            return None

        # Execute static XOR decryption
        plaintext_str, plaintext_bytes = self._run_xor(data, key_bytes)

        # If further pipeline stages exist: e.g. | Out-String, | iex
        remaining_stages = node.elements[2:]

        # Check join semantics: either explicitly requested, converts_to_char is True, or trailing join
        should_join = force_join or converts_to_char

        result_node: ASTNode
        if should_join:
            result_node = StringLiteralNode(value=plaintext_str, is_expandable=False)
        else:
            result_node = ArrayLiteralNode(
                elements=[NumberLiteralNode(value=b, raw=str(b)) for b in plaintext_bytes]
            )

        if remaining_stages:
            return PipelineNode(elements=[result_node] + remaining_stages)

        return result_node

    def _decrypt_static_encoding_call(self, node: StaticMemberAccessNode) -> Optional[ASTNode]:
        """Resolves [System.Text.Encoding]::ASCII.GetString($pipeline) calls."""
        type_norm = node.type_name.strip("[]").lower()
        if not (type_norm.endswith("encoding") or type_norm in ("ascii", "utf8", "unicode")):
            return None

        member_norm = node.member.lower()
        if member_norm != "getstring" or not node.arguments:
            return None

        arg = node.arguments[0]
        pipe_node = None
        if isinstance(arg, PipelineNode):
            pipe_node = arg
        elif isinstance(arg, ParenthesizedExpressionNode) and isinstance(arg.expression, PipelineNode):
            pipe_node = arg.expression

        if pipe_node is not None:
            dec = self._decrypt_pipeline(pipe_node, force_join=True)
            if dec is not None:
                return dec

        return None

    def _decrypt_method_call(self, node: MethodCallNode) -> Optional[ASTNode]:
        """Resolves .GetString(...) invocations on text encoding objects."""
        if node.method_name.lower() != "getstring" or not node.arguments:
            return None

        is_encoding = False
        encoding = "ascii"
        target = node.target
        if isinstance(target, StaticMemberAccessNode):
            type_norm = target.type_name.strip("[]").lower()
            if type_norm.endswith("encoding") or type_norm in ("ascii", "utf8", "unicode"):
                is_encoding = True
                tm = target.member.lower()
                if "utf8" in tm or "utf-8" in tm:
                    encoding = "utf-8"
                elif "unicode" in tm or "utf16" in tm:
                    encoding = "utf-16le"
                elif "ascii" in tm:
                    encoding = "ascii"
        elif isinstance(target, MemberAccessNode):
            member_norm = target.member.lower()
            if member_norm in ("ascii", "utf8", "unicode", "default"):
                is_encoding = True
                if "utf8" in member_norm:
                    encoding = "utf-8"
                elif "unicode" in member_norm:
                    encoding = "utf-16le"
        elif isinstance(target, VariableNode):
            var_name = target.name.lower()
            if "enc" in var_name or "utf" in var_name or "ascii" in var_name:
                is_encoding = True

        if not is_encoding:
            return None

        arg = node.arguments[0]
        pipe_node = None
        if isinstance(arg, PipelineNode):
            pipe_node = arg
        elif isinstance(arg, ParenthesizedExpressionNode) and isinstance(arg.expression, PipelineNode):
            pipe_node = arg.expression

        if pipe_node is not None:
            dec = self._decrypt_pipeline(pipe_node, force_join=True)
            if dec is not None:
                return dec

        raw_bytes = self._extract_bytes(arg)
        if raw_bytes is not None and 0 < len(raw_bytes) <= MAX_LOOP_ITERATIONS:
            try:
                plaintext = bytes(raw_bytes).decode(encoding, errors="replace")
                return StringLiteralNode(value=plaintext, is_expandable=False)
            except Exception:
                pass

        return None

    def _decrypt_for_loop(self, node: ForStatementNode) -> Optional[ASTNode]:
        """Statically simulates and reduces an imperative for loop doing XOR decryption."""
        if not node.initializer or not node.condition or not node.body:
            return None

        # 1. Extract initialization: $i = 0 or $i = 0; $out = ''
        loop_var, start_idx = self._extract_for_initializer(node.initializer)
        if loop_var is None or start_idx is None:
            return None

        # 2. Extract bound from condition: $i -lt $enc.Length or $i -lt 100
        data_node, end_idx = self._extract_for_condition(node.condition, loop_var)
        if data_node is None and end_idx is None:
            return None

        # Extract data bytes
        data: Optional[List[int]] = None
        if data_node is not None:
            data = self._extract_bytes(data_node)
        elif end_idx is not None:
            data = None  # Will check body for array index access

        # 3. Analyze body statements
        body_stmts = node.body.statements if isinstance(node.body, ScriptBlockNode) else [node.body]
        if not body_stmts:
            return None

        # Look for accumulator pattern: $out += [char]($enc[$i] -bxor $key)
        # or in-place mutation: $b[$i] = $b[$i] -bxor $key
        for stmt in body_stmts:
            if isinstance(stmt, AssignmentNode):
                # Pattern A: $out += [char]($enc[$i] -bxor $key)
                if isinstance(stmt.variable, VariableNode):
                    dest_var = stmt.variable.name.lower()
                    xor_analysis = self._analyze_loop_xor_expr(stmt.expression, loop_var)
                    if xor_analysis is not None:
                        source_arr_node, key_bytes, to_char = xor_analysis
                        target_data = data or (self._extract_bytes(source_arr_node) if source_arr_node else None)
                        if target_data is not None and 0 < len(target_data) <= MAX_LOOP_ITERATIONS:
                            dec_str, dec_bytes = self._run_xor(target_data, key_bytes)
                            if to_char:
                                self.symbols[dest_var] = dec_str
                                return AssignmentNode(
                                    variable=VariableNode(name=stmt.variable.name),
                                    expression=StringLiteralNode(value=dec_str, is_expandable=False),
                                )
                            else:
                                self.symbols[dest_var] = dec_bytes
                                return AssignmentNode(
                                    variable=VariableNode(name=stmt.variable.name),
                                    expression=ArrayLiteralNode(
                                        elements=[NumberLiteralNode(value=b, raw=str(b)) for b in dec_bytes]
                                    ),
                                )

                # Pattern B: In-place mutation: $b[$i] = $b[$i] -bxor $key
                elif isinstance(stmt.variable, IndexAccessNode):
                    arr_target = stmt.variable.target
                    if isinstance(arr_target, VariableNode):
                        arr_var = arr_target.name.lower()
                        xor_analysis = self._analyze_loop_xor_expr(stmt.expression, loop_var)
                        if xor_analysis is not None:
                            _, key_bytes, to_char = xor_analysis
                            target_data = data or (self.symbols.get(arr_var) if arr_var in self.symbols else None)
                            if target_data is not None and 0 < len(target_data) <= MAX_LOOP_ITERATIONS:
                                dec_str, dec_bytes = self._run_xor(target_data, key_bytes)
                                self.symbols[arr_var] = dec_bytes
                                return AssignmentNode(
                                    variable=VariableNode(name=arr_target.name),
                                    expression=ArrayLiteralNode(
                                        elements=[NumberLiteralNode(value=b, raw=str(b)) for b in dec_bytes]
                                    ),
                                )

        return None

    def _decrypt_foreach_loop(self, node: ForEachStatementNode) -> Optional[ASTNode]:
        """Statically simulates and reduces an imperative foreach ($b in $enc) loop."""
        if not node.variable or not node.collection or not node.body:
            return None

        var_name = getattr(node.variable, "name", str(node.variable)).lower().lstrip("$")
        data = self._extract_bytes(node.collection)
        if data is None or len(data) == 0 or len(data) > MAX_LOOP_ITERATIONS:
            return None

        body_stmts = node.body.statements if isinstance(node.body, ScriptBlockNode) else [node.body]
        for stmt in body_stmts:
            if isinstance(stmt, AssignmentNode) and isinstance(stmt.variable, VariableNode):
                dest_var = stmt.variable.name.lower()
                xor_analysis = self._analyze_loop_xor_expr(stmt.expression, var_name)
                if xor_analysis is not None:
                    _, key_bytes, to_char = xor_analysis
                    dec_str, dec_bytes = self._run_xor(data, key_bytes)
                    if to_char:
                        self.symbols[dest_var] = dec_str
                        return AssignmentNode(
                            variable=VariableNode(name=stmt.variable.name),
                            expression=StringLiteralNode(value=dec_str, is_expandable=False),
                        )
                    else:
                        self.symbols[dest_var] = dec_bytes
                        return AssignmentNode(
                            variable=VariableNode(name=stmt.variable.name),
                            expression=ArrayLiteralNode(
                                elements=[NumberLiteralNode(value=b, raw=str(b)) for b in dec_bytes]
                            ),
                        )

        return None

    def _decrypt_while_loop(self, node: WhileStatementNode) -> Optional[ASTNode]:
        """Statically reduces while ($i -lt $len) loops doing XOR decryption."""
        # Check condition for $i -lt bound
        if not isinstance(node.condition, BinaryOpNode) or node.condition.operator.lower() not in ("-lt", "-le"):
            return None

        left = node.condition.left
        loop_var = left.name.lower() if isinstance(left, VariableNode) else None
        if not loop_var:
            return None

        data_node, _ = self._extract_for_condition(node.condition, loop_var)
        data = self._extract_bytes(data_node) if data_node else None

        body_stmts = node.body.statements if isinstance(node.body, ScriptBlockNode) else [node.body]
        for stmt in body_stmts:
            if isinstance(stmt, AssignmentNode) and isinstance(stmt.variable, VariableNode):
                dest_var = stmt.variable.name.lower()
                xor_analysis = self._analyze_loop_xor_expr(stmt.expression, loop_var)
                if xor_analysis is not None:
                    src_arr, key_bytes, to_char = xor_analysis
                    target_data = data or (self._extract_bytes(src_arr) if src_arr else None)
                    if target_data is not None and 0 < len(target_data) <= MAX_LOOP_ITERATIONS:
                        dec_str, dec_bytes = self._run_xor(target_data, key_bytes)
                        if to_char:
                            self.symbols[dest_var] = dec_str
                            return AssignmentNode(
                                variable=VariableNode(name=stmt.variable.name),
                                expression=StringLiteralNode(value=dec_str, is_expandable=False),
                            )
                        else:
                            self.symbols[dest_var] = dec_bytes
                            return AssignmentNode(
                                variable=VariableNode(name=stmt.variable.name),
                                expression=ArrayLiteralNode(
                                    elements=[NumberLiteralNode(value=b, raw=str(b)) for b in dec_bytes]
                                ),
                            )

        return None

    def _analyze_xor_body(self, node: ASTNode) -> Optional[Tuple[List[int], bool]]:
        """Extracts key bytes and character cast intent from a pipeline foreach body."""
        to_char = False
        target = node

        # Check for [char](...) cast
        if isinstance(target, TypeCastNode):
            alias = TypeAcceleratorRegistry.get_canonical_alias(target.type_name).lower()
            if alias == "char":
                to_char = True
                target = target.expression

        if isinstance(target, ParenthesizedExpressionNode):
            target = target.expression

        # Binary XOR: $_ -bxor key or key -bxor $_
        if isinstance(target, BinaryOpNode) and target.operator.lower() in ("-bxor", "^"):
            key_bytes = None
            if self._is_pipeline_var(target.left):
                key_bytes = self._extract_key(target.right)
            elif self._is_pipeline_var(target.right):
                key_bytes = self._extract_key(target.left)

            if key_bytes is not None:
                return key_bytes, to_char

        return None

    def _analyze_loop_xor_expr(
        self, expr: ASTNode, loop_var: str
    ) -> Optional[Tuple[Optional[ASTNode], List[int], bool]]:
        """Analyzes an assignment expression within a loop to extract source array and XOR key."""
        to_char = False
        target = expr

        # Check compound assignment: $out + [char](...)
        if isinstance(target, BinaryOpNode) and target.operator == "+":
            target = target.right

        if isinstance(target, TypeCastNode):
            alias = TypeAcceleratorRegistry.get_canonical_alias(target.type_name).lower()
            if alias == "char":
                to_char = True
                target = target.expression

        if isinstance(target, ParenthesizedExpressionNode):
            target = target.expression

        if isinstance(target, BinaryOpNode) and target.operator.lower() in ("-bxor", "^"):
            # One side is $enc[$i] or $b, other is key
            src_node = None
            key_bytes = None

            left = target.left
            right = target.right

            if self._is_loop_index_access(left, loop_var) or self._is_loop_var(left, loop_var):
                src_node = getattr(left, "target", None)
                key_bytes = self._extract_key(right)
            elif self._is_loop_index_access(right, loop_var) or self._is_loop_var(right, loop_var):
                src_node = getattr(right, "target", None)
                key_bytes = self._extract_key(left)

            if key_bytes is not None:
                return src_node, key_bytes, to_char

        return None

    def _is_loop_index_access(self, node: ASTNode, loop_var: str) -> bool:
        """Checks if node is $arr[$i] where index is loop_var."""
        if isinstance(node, IndexAccessNode):
            idx = node.index
            if isinstance(idx, VariableNode) and idx.name.lower() == loop_var:
                return True
        return False

    def _is_loop_var(self, node: ASTNode, loop_var: str) -> bool:
        return isinstance(node, VariableNode) and node.name.lower() == loop_var

    def _is_pipeline_var(self, node: ASTNode) -> bool:
        return isinstance(node, VariableNode) and node.name.lower() in ("_", "psitem")

    def _is_foreach_stage(self, stage: ASTNode) -> bool:
        if isinstance(stage, CommandNode):
            name = getattr(stage.target, "name", str(getattr(stage.target, "value", ""))).lower()
            return name in ("%", "foreach-object", "foreach")
        return False

    def _get_script_block_from_stage(self, stage: ASTNode) -> Optional[ScriptBlockNode]:
        if isinstance(stage, CommandNode):
            for arg in stage.arguments:
                if isinstance(arg, ScriptBlockNode):
                    return arg
                if isinstance(arg, ParenthesizedExpressionNode) and isinstance(arg.expression, ScriptBlockNode):
                    return arg.expression
        return None

    def _extract_for_initializer(self, node: ASTNode) -> Tuple[Optional[str], Optional[int]]:
        if isinstance(node, AssignmentNode) and isinstance(node.variable, VariableNode):
            val_node = node.expression
            if isinstance(val_node, NumberLiteralNode):
                return node.variable.name.lower(), int(val_node.value)
        return None, None

    def _extract_for_condition(self, node: ASTNode, loop_var: str) -> Tuple[Optional[ASTNode], Optional[int]]:
        if isinstance(node, BinaryOpNode) and node.operator.lower() in ("-lt", "-le"):
            left = node.left
            right = node.right
            if isinstance(left, VariableNode) and left.name.lower() == loop_var:
                if isinstance(right, MemberAccessNode) and right.member.lower() in ("length", "count"):
                    return right.target, None
                if isinstance(right, NumberLiteralNode):
                    return None, int(right.value)
        return None, None

    def _extract_bytes(self, node: ASTNode) -> Optional[List[int]]:
        """Extracts list of byte/int values from an AST node or tracked symbols."""
        if isinstance(node, ArrayLiteralNode):
            bytes_list = []
            for elem in node.elements:
                if isinstance(elem, NumberLiteralNode):
                    bytes_list.append(int(elem.value) & 0xFF)
                elif isinstance(elem, VariableNode) and elem.name.lower() in self.symbols:
                    s_val = self.symbols[elem.name.lower()]
                    if isinstance(s_val, int):
                        bytes_list.append(s_val & 0xFF)
                    else:
                        return None
                else:
                    return None
            return bytes_list

        if isinstance(node, RangeExpressionNode):
            if isinstance(node.start, NumberLiteralNode) and isinstance(node.end, NumberLiteralNode):
                st = int(node.start.value)
                ed = int(node.end.value)
                if abs(ed - st) < MAX_LOOP_ITERATIONS:
                    step = 1 if ed >= st else -1
                    return [(x & 0xFF) for x in range(st, ed + step, step)]

        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_bytes(node.expression)

        if isinstance(node, VariableNode):
            name = node.name.lower()
            if name in self.symbols:
                s = self.symbols[name]
                if isinstance(s, list) and all(isinstance(x, int) for x in s):
                    return [x & 0xFF for x in s]
                if isinstance(s, (bytes, bytearray)):
                    return list(s)
                if isinstance(s, str):
                    return [ord(c) & 0xFF for c in s]

        if isinstance(node, StringLiteralNode):
            return [ord(c) & 0xFF for c in node.value]

        # [Convert]::FromBase64String('...')
        if isinstance(node, StaticMemberAccessNode):
            if node.type_name.strip("[]").lower().endswith("convert") and node.member.lower() == "frombase64string":
                if node.arguments and isinstance(node.arguments[0], StringLiteralNode):
                    try:
                        raw = base64.b64decode(node.arguments[0].value)
                        return list(raw)
                    except Exception:
                        pass

        return None

    def _extract_key(self, node: ASTNode) -> Optional[List[int]]:
        """Extracts key material as a list of integers from a literal, variable, or array."""
        if isinstance(node, NumberLiteralNode):
            return [int(node.value) & 0xFF]

        if isinstance(node, StringLiteralNode):
            return [ord(c) & 0xFF for c in node.value]

        if isinstance(node, ArrayLiteralNode):
            keys = []
            for elem in node.elements:
                if isinstance(elem, NumberLiteralNode):
                    keys.append(int(elem.value) & 0xFF)
                else:
                    return None
            return keys if keys else None

        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_key(node.expression)

        if isinstance(node, VariableNode):
            name = node.name.lower()
            if name in self.symbols:
                val = self.symbols[name]
                if isinstance(val, int):
                    return [val & 0xFF]
                if isinstance(val, list) and all(isinstance(x, int) for x in val):
                    return [x & 0xFF for x in val]
                if isinstance(val, str):
                    return [ord(c) & 0xFF for c in val]

        # Multi-byte index expression: $key[$i++ % $key.Length]
        if isinstance(node, IndexAccessNode):
            return self._extract_key(node.target)

        return None

    def _run_xor(self, data: List[int], key: List[int]) -> Tuple[str, List[int]]:
        """Executes XOR decryption with zeroization of intermediate buffers."""
        k_len = len(key)
        if k_len == 0:
            return "", []

        decrypted_buf = bytearray(len(data))
        try:
            for i, b in enumerate(data):
                decrypted_buf[i] = b ^ key[i % k_len]

            # Try decoding as ASCII / UTF-8 string
            try:
                plaintext_str = decrypted_buf.decode("utf-8")
            except UnicodeDecodeError:
                plaintext_str = "".join(chr(b) if 32 <= b <= 126 or b in (9, 10, 13) else f"\\x{b:02x}" for b in decrypted_buf)

            decrypted_list = list(decrypted_buf)
            return plaintext_str, decrypted_list
        finally:
            if decrypted_buf:
                zeroize_buffer(decrypted_buf)
