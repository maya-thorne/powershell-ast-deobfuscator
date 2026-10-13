"""
PowerShell AST Pipeline Optimizer.
Optimizes pipeline stages and evaluates static pipelines (| %, | ForEach-Object, | Select-Object, | Where-Object).
"""

import copy
import fnmatch
from typing import Any, Dict, List, Optional, Set

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
    TypeCastNode,
    UnaryOpNode,
    VariableNode,
    WhileStatementNode,
)
from .type_accelerators import TypeAcceleratorRegistry


class PowerShellPipelineOptimizer:
    """
    Compiler-grade pipeline optimizer for PowerShell AST.
    Evaluates static collection pipelines, unfolds Foreach mappings,
    simplifies Select slices and unique filters, evaluates Where predicates,
    and simplifies piped command invocations.
    """

    MAX_EXPAND_RANGE = 10000

    def __init__(self, symbols: Optional[Dict[str, Any]] = None):
        self.symbols = symbols if symbols is not None else {}

    def optimize(self, node: ASTNode) -> ASTNode:
        """Entry point for pipeline AST optimization."""
        return self.visit(node)

    def visit(self, node: ASTNode) -> ASTNode:
        if isinstance(node, ScriptBlockNode):
            return self.visit_script_block(node)
        elif isinstance(node, PipelineNode):
            return self.visit_pipeline(node)
        elif isinstance(node, AssignmentNode):
            return self.visit_assignment(node)
        elif isinstance(node, ParenthesizedExpressionNode):
            return self.visit_parenthesized(node)
        elif isinstance(node, FormatOpNode):
            norm_fmt = self.visit(node.format_string)
            norm_args = [self.visit(a) for a in node.arguments]
            return FormatOpNode(format_string=norm_fmt, arguments=norm_args)
        elif isinstance(node, BinaryOpNode):
            return BinaryOpNode(left=self.visit(node.left), operator=node.operator, right=self.visit(node.right))
        elif isinstance(node, UnaryOpNode):
            return UnaryOpNode(operator=node.operator, operand=self.visit(node.operand))
        elif isinstance(node, IndexAccessNode):
            return IndexAccessNode(target=self.visit(node.target), index=self.visit(node.index))
        elif isinstance(node, TypeCastNode):
            return TypeCastNode(type_name=node.type_name, expression=self.visit(node.expression))
        elif isinstance(node, MemberAccessNode):
            return MemberAccessNode(target=self.visit(node.target), member=node.member)
        elif isinstance(node, MethodCallNode):
            return MethodCallNode(
                target=self.visit(node.target),
                method_name=node.method_name,
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, DynamicMemberAccessNode):
            return DynamicMemberAccessNode(target=self.visit(node.target), member_expr=self.visit(node.member_expr))
        elif isinstance(node, DynamicMethodCallNode):
            return DynamicMethodCallNode(
                target=self.visit(node.target),
                method_expr=self.visit(node.method_expr),
                arguments=[self.visit(a) for a in node.arguments],
            )
        elif isinstance(node, StaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return StaticMemberAccessNode(type_name=node.type_name, member=node.member, arguments=norm_args)
        elif isinstance(node, DynamicStaticMemberAccessNode):
            norm_args = [self.visit(a) for a in node.arguments] if node.arguments is not None else None
            return DynamicStaticMemberAccessNode(
                type_name=node.type_name,
                member_expr=self.visit(node.member_expr),
                arguments=norm_args,
            )
        elif isinstance(node, IfStatementNode):
            return IfStatementNode(
                condition=self.visit(node.condition),
                then_branch=self.visit(node.then_branch),
                else_branch=self.visit(node.else_branch) if node.else_branch else None,
            )
        elif isinstance(node, WhileStatementNode):
            return WhileStatementNode(condition=self.visit(node.condition), body=self.visit(node.body))
        elif isinstance(node, CommandNode):
            return CommandNode(target=self.visit(node.target), arguments=[self.visit(a) for a in node.arguments])
        elif isinstance(node, ArrayLiteralNode):
            return ArrayLiteralNode(elements=[self.visit(e) for e in node.elements])
        return node

    def visit_script_block(self, node: ScriptBlockNode) -> ScriptBlockNode:
        return ScriptBlockNode(
            statements=[self.visit(s) for s in node.statements],
            is_nested=node.is_nested,
        )

    def visit_assignment(self, node: AssignmentNode) -> AssignmentNode:
        expr = self.visit(node.expression)
        return AssignmentNode(variable=node.variable, expression=expr)

    def visit_parenthesized(self, node: ParenthesizedExpressionNode) -> ASTNode:
        inner = self.visit(node.expression)
        return ParenthesizedExpressionNode(expression=inner)

    def visit_pipeline(self, node: PipelineNode) -> ASTNode:
        if not node.elements:
            return node

        # Step 1: Recursively optimize child elements
        optimized_elements = [self.visit(e) for e in node.elements]
        current: ASTNode = optimized_elements[0]

        # Step 2: Iterate and fold pipeline stages from left to right
        i = 1
        while i < len(optimized_elements):
            stage = optimized_elements[i]
            folded = self._try_fold_pipeline_stage(current, stage)
            if folded is not None:
                current = folded
                i += 1
            else:
                # Stage could not be folded statically; keep current and remaining pipeline
                remaining = [current] + optimized_elements[i:]
                return PipelineNode(elements=remaining)

        return current

    def _try_fold_pipeline_stage(self, source: ASTNode, stage: ASTNode) -> Optional[ASTNode]:
        """Attempts to statically fold source | stage into a simplified AST node."""
        cmd_name = self._get_command_name(stage)
        if not cmd_name:
            return None

        # 1. ForEach-Object / % / foreach
        if cmd_name in ("%", "foreach", "foreach-object"):
            return self._fold_foreach_stage(source, stage)

        # 2. Select-Object / select
        if cmd_name in ("select", "select-object"):
            return self._fold_select_stage(source, stage)

        # 3. Where-Object / ? / where
        if cmd_name in ("?", "where", "where-object"):
            return self._fold_where_stage(source, stage)

        # 4. Out-String
        if cmd_name == "out-string":
            return self._fold_out_string_stage(source, stage)

        # 5. Invoke-Expression / iex
        if cmd_name in ("iex", "invoke-expression"):
            return self._fold_iex_stage(source, stage)

        return None

    def _get_command_name(self, stage: ASTNode) -> Optional[str]:
        if isinstance(stage, CommandNode):
            if isinstance(stage.target, IdentifierNode):
                return stage.target.name.lower().replace("`", "")
            if isinstance(stage.target, StringLiteralNode):
                return stage.target.value.lower().replace("`", "")
        if isinstance(stage, IdentifierNode):
            return stage.name.lower().replace("`", "")
        if isinstance(stage, StringLiteralNode):
            return stage.value.lower().replace("`", "")
        return None

    def _extract_collection(self, node: ASTNode) -> Optional[List[ASTNode]]:
        """Extracts a static list of AST items from an array, range, or parenthesized collection."""
        if isinstance(node, ParenthesizedExpressionNode):
            return self._extract_collection(node.expression)

        if isinstance(node, ArrayLiteralNode):
            return list(node.elements)

        if isinstance(node, RangeExpressionNode):
            start = node.start
            end = node.end
            if isinstance(start, NumberLiteralNode) and isinstance(end, NumberLiteralNode):
                try:
                    s_val = int(start.value)
                    e_val = int(end.value)
                    if abs(e_val - s_val) <= self.MAX_EXPAND_RANGE:
                        step = 1 if e_val >= s_val else -1
                        return [
                            NumberLiteralNode(value=v, raw=str(v))
                            for v in range(s_val, e_val + step, step)
                        ]
                except (ValueError, OverflowError):
                    pass

        if isinstance(node, (NumberLiteralNode, StringLiteralNode)):
            return [node]

        return None

    def _fold_foreach_stage(self, source: ASTNode, stage: CommandNode) -> Optional[ASTNode]:
        """Folds collection | % { [char]$_ } into ArrayLiteralNode of evaluated items."""
        # Locate the ScriptBlock argument in stage.arguments
        script_block: Optional[ScriptBlockNode] = None
        for arg in stage.arguments:
            if isinstance(arg, ScriptBlockNode):
                script_block = arg
                break
            elif isinstance(arg, ParenthesizedExpressionNode) and isinstance(arg.expression, ScriptBlockNode):
                script_block = arg.expression
                break

        if script_block is None or not script_block.statements:
            # Check if Foreach-Object was invoked with property name: % Length
            if len(stage.arguments) == 1 and isinstance(stage.arguments[0], IdentifierNode):
                prop_name = stage.arguments[0].name.lower()
                items = self._extract_collection(source)
                if items is not None:
                    mapped = []
                    for it in items:
                        if isinstance(it, StringLiteralNode) and prop_name == "length":
                            mapped.append(NumberLiteralNode(value=len(it.value), raw=str(len(it.value))))
                        else:
                            return None
                    return ArrayLiteralNode(elements=mapped)
            return None

        items = self._extract_collection(source)
        if items is None:
            return None

        # If identity mapping: % { $_ } or % { $PSItem }
        if len(script_block.statements) == 1:
            stmt = script_block.statements[0]
            if isinstance(stmt, VariableNode) and stmt.name.lower() in ("_", "psitem"):
                return source

        body_stmt = script_block.statements[0]
        transformed_items: List[ASTNode] = []

        for item in items:
            res = self._eval_foreach_item(body_stmt, item)
            if res is None:
                return None
            transformed_items.append(res)

        # If the input was a single scalar literal and resulted in 1 item
        if isinstance(source, (NumberLiteralNode, StringLiteralNode)) and len(transformed_items) == 1:
            return transformed_items[0]

        return ArrayLiteralNode(elements=transformed_items)

    def _eval_foreach_item(self, body: ASTNode, current_item: ASTNode) -> Optional[ASTNode]:
        """Evaluates an expression body for a single pipeline item substituting $_."""
        subst = self._substitute_var(body, current_item)

        # 1. Type cast: [char]$_, [int]$_, [byte]$_
        if isinstance(subst, TypeCastNode):
            alias = TypeAcceleratorRegistry.get_canonical_alias(subst.type_name).lower()
            inner = subst.expression
            if isinstance(inner, NumberLiteralNode):
                try:
                    val = int(inner.value)
                    if alias == "char" and 0 <= val <= 0x10FFFF:
                        return StringLiteralNode(value=chr(val), is_expandable=False)
                    elif alias in ("int", "int32", "int16", "int64"):
                        return NumberLiteralNode(value=val, raw=str(val))
                    elif alias == "byte" and 0 <= val <= 255:
                        return NumberLiteralNode(value=val, raw=str(val))
                except (ValueError, OverflowError):
                    pass
            elif isinstance(inner, StringLiteralNode):
                s = inner.value.strip()
                if alias == "char":
                    if len(s) == 1:
                        return StringLiteralNode(value=s, is_expandable=False)
                    elif s.startswith("0x") or s.isdigit():
                        try:
                            code = int(s, 16 if s.startswith("0x") else 10)
                            if 0 <= code <= 0x10FFFF:
                                return StringLiteralNode(value=chr(code), is_expandable=False)
                        except ValueError:
                            pass
                elif alias in ("int", "int32"):
                    try:
                        code = int(s, 16 if s.startswith("0x") else 10)
                        return NumberLiteralNode(value=code, raw=str(code))
                    except ValueError:
                        pass

        # 2. Binary operations: $_ -bxor 35, $_ + 1, $_ - 1, $_ -band 0xFF
        if isinstance(subst, BinaryOpNode):
            left = self._eval_foreach_item(subst.left, current_item) or subst.left
            right = self._eval_foreach_item(subst.right, current_item) or subst.right
            if isinstance(left, NumberLiteralNode) and isinstance(right, NumberLiteralNode):
                try:
                    l_val = int(left.value)
                    r_val = int(right.value)
                    op = subst.operator.lower()
                    if op in ("-bxor", "^"):
                        res = l_val ^ r_val
                        return NumberLiteralNode(value=res, raw=str(res))
                    elif op in ("-band", "&"):
                        res = l_val & r_val
                        return NumberLiteralNode(value=res, raw=str(res))
                    elif op in ("-bor", "|"):
                        res = l_val | r_val
                        return NumberLiteralNode(value=res, raw=str(res))
                    elif op in ("-shl", "<<"):
                        res = l_val << r_val
                        return NumberLiteralNode(value=res, raw=str(res))
                    elif op in ("-shr", ">>"):
                        res = l_val >> r_val
                        return NumberLiteralNode(value=res, raw=str(res))
                    elif op == "+":
                        res = l_val + r_val
                        return NumberLiteralNode(value=res, raw=str(res))
                    elif op == "-":
                        res = l_val - r_val
                        return NumberLiteralNode(value=res, raw=str(res))
                except (ValueError, OverflowError):
                    pass
            elif isinstance(left, StringLiteralNode) and isinstance(right, StringLiteralNode):
                if subst.operator == "+":
                    return StringLiteralNode(value=left.value + right.value, is_expandable=left.is_expandable)

        # 3. Method calls on $_: $_.ToString(), $_.Trim(), $_.Substring(), $_.Replace()
        if isinstance(subst, MethodCallNode):
            target = self._eval_foreach_item(subst.target, current_item) or subst.target
            m_name = subst.method_name.lower()
            if isinstance(target, StringLiteralNode):
                if m_name == "tostring":
                    return target
                elif m_name == "trim":
                    return StringLiteralNode(value=target.value.strip(), is_expandable=target.is_expandable)
                elif m_name == "tolower":
                    return StringLiteralNode(value=target.value.lower(), is_expandable=target.is_expandable)
                elif m_name == "toupper":
                    return StringLiteralNode(value=target.value.upper(), is_expandable=target.is_expandable)
                elif m_name == "replace" and len(subst.arguments) == 2:
                    old_a = subst.arguments[0]
                    new_a = subst.arguments[1]
                    if isinstance(old_a, StringLiteralNode) and isinstance(new_a, StringLiteralNode):
                        return StringLiteralNode(value=target.value.replace(old_a.value, new_a.value))
                elif m_name == "substring":
                    if len(subst.arguments) >= 1 and isinstance(subst.arguments[0], NumberLiteralNode):
                        start_idx = int(subst.arguments[0].value)
                        if len(subst.arguments) == 1:
                            return StringLiteralNode(value=target.value[start_idx:])
                        elif isinstance(subst.arguments[1], NumberLiteralNode):
                            sub_len = int(subst.arguments[1].value)
                            return StringLiteralNode(value=target.value[start_idx:start_idx + sub_len])
            elif isinstance(target, NumberLiteralNode):
                if m_name == "tostring":
                    if len(subst.arguments) == 1 and isinstance(subst.arguments[0], StringLiteralNode):
                        fmt = subst.arguments[0].value
                        if fmt.upper().startswith("X"):
                            pad = int(fmt[1:]) if len(fmt) > 1 and fmt[1:].isdigit() else 0
                            hex_str = format(int(target.value), f"0{pad}X" if fmt.isupper() else f"0{pad}x")
                            return StringLiteralNode(value=hex_str)
                    return StringLiteralNode(value=str(target.value))

        # 4. Member property access: $_.Length
        if isinstance(subst, MemberAccessNode):
            target = self._eval_foreach_item(subst.target, current_item) or subst.target
            if isinstance(target, StringLiteralNode) and subst.member.lower() == "length":
                return NumberLiteralNode(value=len(target.value), raw=str(len(target.value)))

        # 5. Format operator: "{0:X2}" -f $_
        if isinstance(subst, FormatOpNode):
            fmt_str = subst.format_string
            if isinstance(fmt_str, StringLiteralNode) and subst.arguments:
                arg_vals = []
                for a in subst.arguments:
                    eval_a = self._eval_foreach_item(a, current_item) or a
                    if isinstance(eval_a, (StringLiteralNode, NumberLiteralNode)):
                        arg_vals.append(eval_a.value)
                    else:
                        return subst
                try:
                    res_str = fmt_str.value
                    for idx, val in enumerate(arg_vals):
                        placeholder = f"{{{idx}}}"
                        if placeholder in res_str:
                            res_str = res_str.replace(placeholder, str(val))
                    return StringLiteralNode(value=res_str, is_expandable=fmt_str.is_expandable)
                except Exception:
                    pass

        # 6. Fallback: return substituted node if it resolved to literal
        if isinstance(subst, (StringLiteralNode, NumberLiteralNode)):
            return subst

        return subst

    def _substitute_var(self, node: ASTNode, replacement: ASTNode) -> ASTNode:
        """Substitutes VariableNode(name='_') or '$PSItem' with replacement AST node."""
        if isinstance(node, VariableNode):
            if node.name.lower() in ("_", "psitem"):
                return copy.deepcopy(replacement)
            return node

        if isinstance(node, TypeCastNode):
            return TypeCastNode(
                type_name=node.type_name,
                expression=self._substitute_var(node.expression, replacement),
            )

        if isinstance(node, BinaryOpNode):
            return BinaryOpNode(
                left=self._substitute_var(node.left, replacement),
                operator=node.operator,
                right=self._substitute_var(node.right, replacement),
            )

        if isinstance(node, UnaryOpNode):
            return UnaryOpNode(
                operator=node.operator,
                operand=self._substitute_var(node.operand, replacement),
            )

        if isinstance(node, MemberAccessNode):
            return MemberAccessNode(
                target=self._substitute_var(node.target, replacement),
                member=node.member,
            )

        if isinstance(node, MethodCallNode):
            return MethodCallNode(
                target=self._substitute_var(node.target, replacement),
                method_name=node.method_name,
                arguments=[self._substitute_var(a, replacement) for a in node.arguments],
            )

        if isinstance(node, FormatOpNode):
            return FormatOpNode(
                format_string=self._substitute_var(node.format_string, replacement),
                arguments=[self._substitute_var(a, replacement) for a in node.arguments],
            )

        if isinstance(node, ParenthesizedExpressionNode):
            return ParenthesizedExpressionNode(
                expression=self._substitute_var(node.expression, replacement)
            )

        if isinstance(node, IndexAccessNode):
            return IndexAccessNode(
                target=self._substitute_var(node.target, replacement),
                index=self._substitute_var(node.index, replacement),
            )

        return node

    def _fold_select_stage(self, source: ASTNode, stage: ASTNode) -> Optional[ASTNode]:
        """Folds collection | Select-Object -First N, -Last N, -Skip N, -Unique, -ExpandProperty."""
        items = self._extract_collection(source)
        if items is None:
            return None

        # Parse select parameters
        first_n: Optional[int] = None
        last_n: Optional[int] = None
        skip_n: Optional[int] = None
        indices: Optional[List[int]] = None
        unique_flag = False
        expand_prop: Optional[str] = None

        idx = 0
        args = stage.arguments if isinstance(stage, CommandNode) else []
        while idx < len(args):
            arg = args[idx]
            arg_str = getattr(arg, "name", str(getattr(arg, "value", ""))).lower()

            if arg_str in ("-first", "first") and idx + 1 < len(args):
                val_node = args[idx + 1]
                if isinstance(val_node, NumberLiteralNode):
                    first_n = int(val_node.value)
                    idx += 2
                    continue
            elif arg_str in ("-last", "last") and idx + 1 < len(args):
                val_node = args[idx + 1]
                if isinstance(val_node, NumberLiteralNode):
                    last_n = int(val_node.value)
                    idx += 2
                    continue
            elif arg_str in ("-skip", "skip") and idx + 1 < len(args):
                val_node = args[idx + 1]
                if isinstance(val_node, NumberLiteralNode):
                    skip_n = int(val_node.value)
                    idx += 2
                    continue
            elif arg_str in ("-index", "index") and idx + 1 < len(args):
                val_node = args[idx + 1]
                if isinstance(val_node, NumberLiteralNode):
                    indices = [int(val_node.value)]
                    idx += 2
                    continue
                elif isinstance(val_node, ArrayLiteralNode):
                    indices = [int(e.value) for e in val_node.elements if isinstance(e, NumberLiteralNode)]
                    idx += 2
                    continue
            elif arg_str in ("-unique", "unique"):
                unique_flag = True
                idx += 1
                continue
            elif arg_str in ("-expandproperty", "expandproperty") and idx + 1 < len(args):
                prop_node = args[idx + 1]
                expand_prop = getattr(prop_node, "name", str(getattr(prop_node, "value", ""))).lower()
                idx += 2
                continue
            idx += 1

        res_items = list(items)

        if skip_n is not None and skip_n > 0:
            res_items = res_items[skip_n:]

        if first_n is not None and first_n >= 0:
            res_items = res_items[:first_n]

        if last_n is not None and last_n >= 0:
            res_items = res_items[-last_n:] if last_n > 0 else []

        if indices is not None:
            indexed = []
            for i in indices:
                if 0 <= i < len(items):
                    indexed.append(items[i])
            res_items = indexed

        if unique_flag:
            seen: Set[str] = set()
            unique_items = []
            for it in res_items:
                key = str(getattr(it, "value", repr(it)))
                if key not in seen:
                    seen.add(key)
                    unique_items.append(it)
            res_items = unique_items

        if expand_prop:
            if expand_prop == "length":
                res_items = [
                    NumberLiteralNode(value=len(it.value), raw=str(len(it.value)))
                    if isinstance(it, StringLiteralNode) else it
                    for it in res_items
                ]

        if indices is not None and len(indices) == 1 and len(res_items) == 1:
            return res_items[0]

        if len(res_items) == 1 and not isinstance(source, ArrayLiteralNode):
            return res_items[0]

        return ArrayLiteralNode(elements=res_items)

    def _fold_where_stage(self, source: ASTNode, stage: ASTNode) -> Optional[ASTNode]:
        """Folds collection | Where-Object { $_ -gt 10 } into filtered ArrayLiteralNode."""
        args = stage.arguments if isinstance(stage, CommandNode) else []
        script_block: Optional[ScriptBlockNode] = None
        for arg in args:
            if isinstance(arg, ScriptBlockNode):
                script_block = arg
                break
            elif isinstance(arg, ParenthesizedExpressionNode) and isinstance(arg.expression, ScriptBlockNode):
                script_block = arg.expression
                break

        if script_block is None or not script_block.statements:
            return None

        items = self._extract_collection(source)
        if items is None:
            return None

        predicate = script_block.statements[0]
        filtered: List[ASTNode] = []

        for item in items:
            passed = self._eval_predicate(predicate, item)
            if passed is True:
                filtered.append(item)
            elif passed is None:
                return None  # Could not evaluate predicate statically

        return ArrayLiteralNode(elements=filtered)

    def _eval_predicate(self, predicate: ASTNode, item: ASTNode) -> Optional[bool]:
        """Evaluates boolean truthiness of Where predicate on item."""
        subst = self._substitute_var(predicate, item)

        if isinstance(subst, VariableNode):
            name = subst.name.lower()
            if name == "true":
                return True
            if name in ("false", "null"):
                return False

        if isinstance(subst, BinaryOpNode):
            left = self._eval_foreach_item(subst.left, item) or subst.left
            right = self._eval_foreach_item(subst.right, item) or subst.right
            op = subst.operator.lower()

            l_val = getattr(left, "value", None)
            r_val = getattr(right, "value", None)

            if l_val is not None and r_val is not None:
                if op == "-eq":
                    return l_val == r_val
                elif op == "-ne":
                    return l_val != r_val
                elif op == "-gt":
                    return l_val > r_val
                elif op == "-ge":
                    return l_val >= r_val
                elif op == "-lt":
                    return l_val < r_val
                elif op == "-le":
                    return l_val <= r_val
                elif op == "-like":
                    return fnmatch.fnmatch(str(l_val).lower(), str(r_val).lower())
                elif op == "-notlike":
                    return not fnmatch.fnmatch(str(l_val).lower(), str(r_val).lower())

        if isinstance(subst, StringLiteralNode):
            return len(subst.value) > 0

        if isinstance(subst, NumberLiteralNode):
            return subst.value != 0

        return None

    def _fold_out_string_stage(self, source: ASTNode, stage: ASTNode) -> Optional[ASTNode]:
        """Folds collection | Out-String into a joined StringLiteralNode."""
        items = self._extract_collection(source)
        if items is not None and all(isinstance(i, (StringLiteralNode, NumberLiteralNode)) for i in items):
            joined = "\r\n".join(str(i.value) for i in items)
            return StringLiteralNode(value=joined, is_expandable=False)
        return None

    def _fold_iex_stage(self, source: ASTNode, stage: ASTNode) -> Optional[ASTNode]:
        """Transforms 'calc.exe' | iex into canonical iex 'calc.exe'."""
        if isinstance(source, (StringLiteralNode, ParenthesizedExpressionNode, IdentifierNode)):
            return CommandNode(
                target=IdentifierNode(name="iex"),
                arguments=[source],
            )
        return None
