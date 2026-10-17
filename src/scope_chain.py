"""
PowerShell Scope Chain & Symbol Resolution Manager.
Maintains the hierarchical scope stack, implements lexical & runtime scope lookup,
private scope isolation, variable shadowing detection, and def-use chain tracking.
"""

from typing import Any, Dict, List, Optional, Tuple

from .ast_nodes import ASTNode, NumberLiteralNode, StringLiteralNode
from .scope_models import (
    AccessKind,
    ScopeAnalysisSummary,
    ScopeFrame,
    ScopeSymbol,
    ScopeType,
    VarDefinition,
    VarRead,
)


class PowerShellScopeChain:
    """
    Manages the active stack and hierarchy of PowerShell scope frames.
    """

    def __init__(self, initial_symbols: Optional[Dict[str, Any]] = None):
        self._next_scope_id = 0
        self._next_def_id = 1
        self._next_read_id = 1

        # Root Global Frame (Scope 0)
        self.global_frame = ScopeFrame(
            scope_id=self._alloc_scope_id(),
            scope_type=ScopeType.GLOBAL,
            name="global",
            parent=None,
        )

        # Script Frame (Scope 1)
        self.script_frame = ScopeFrame(
            scope_id=self._alloc_scope_id(),
            scope_type=ScopeType.SCRIPT,
            name="script",
            parent=self.global_frame,
        )
        self.global_frame.children.append(self.script_frame)

        # All frames indexed by ID
        self.all_frames: Dict[int, ScopeFrame] = {
            self.global_frame.scope_id: self.global_frame,
            self.script_frame.scope_id: self.script_frame,
        }

        # Active call / block stack
        self._stack: List[ScopeFrame] = [self.global_frame, self.script_frame]

        # Populate pre-configured initial symbols if supplied
        if initial_symbols:
            for k, v in initial_symbols.items():
                self.resolve_write(
                    var_name=k,
                    scope_qualifier="global",
                    value=v,
                    is_constant=True,
                    stmt_idx=0,
                )

    def _alloc_scope_id(self) -> int:
        sid = self._next_scope_id
        self._next_scope_id += 1
        return sid

    @property
    def current_scope(self) -> ScopeFrame:
        """Returns the top of the scope stack."""
        return self._stack[-1]

    def push_scope(self, scope_type: ScopeType, name: str) -> ScopeFrame:
        """Pushes a new child scope onto the stack."""
        new_frame = ScopeFrame(
            scope_id=self._alloc_scope_id(),
            scope_type=scope_type,
            name=name,
            parent=self.current_scope,
        )
        self.current_scope.children.append(new_frame)
        self.all_frames[new_frame.scope_id] = new_frame
        self._stack.append(new_frame)
        return new_frame

    def pop_scope(self) -> ScopeFrame:
        """Pops the top scope from the stack (retains script frame as minimum)."""
        if len(self._stack) > 2:
            return self._stack.pop()
        return self._stack[-1]

    def resolve_target_frame(self, scope_qualifier: Optional[str]) -> ScopeFrame:
        """Resolves target frame based on scope qualifier (global, script, local, numeric, using)."""
        if not scope_qualifier:
            return self.current_scope

        q = scope_qualifier.strip().lower()
        if q == "global":
            return self.global_frame
        if q == "script":
            return self.script_frame
        if q in ("local", "private"):
            return self.current_scope
        if q == "using":
            # Using qualifier accesses variable in parent / enclosing context
            return self.current_scope.parent if self.current_scope.parent else self.global_frame

        # Numeric scope index: 0 = current, 1 = parent, 2 = grandparent...
        if q.isdigit():
            level = int(q)
            curr: Optional[ScopeFrame] = self.current_scope
            for _ in range(level):
                if curr and curr.parent:
                    curr = curr.parent
                else:
                    break
            return curr if curr else self.global_frame

        return self.current_scope

    def resolve_read(
        self,
        var_name: str,
        scope_qualifier: Optional[str] = None,
        ast_node: Optional[ASTNode] = None,
        stmt_idx: int = 0,
    ) -> Tuple[Optional[ScopeSymbol], VarRead]:
        """
        Resolves variable read adhering to PowerShell scope hierarchy and private rules.
        """
        clean_name = var_name.lstrip("$").replace("`", "")
        key = clean_name.lower()
        read_id = self._next_read_id
        self._next_read_id += 1

        matched_sym: Optional[ScopeSymbol] = None
        resolved_scope_id: Optional[int] = None

        if scope_qualifier:
            target_frame = self.resolve_target_frame(scope_qualifier)
            matched_sym = target_frame.get_symbol(key)
            if matched_sym:
                resolved_scope_id = target_frame.scope_id
        else:
            # Unqualified read: Walk upwards from current scope frame to root
            curr: Optional[ScopeFrame] = self.current_scope
            while curr is not None:
                sym = curr.get_symbol(key)
                if sym is not None:
                    # PowerShell private rule: Private variables are strictly isolated to their own frame
                    if sym.is_private and curr.scope_id != self.current_scope.scope_id:
                        curr = curr.parent
                        continue
                    matched_sym = sym
                    resolved_scope_id = curr.scope_id
                    break
                curr = curr.parent

        is_uninit = matched_sym is None or len(matched_sym.definitions) == 0
        reaching_def_id: Optional[int] = None

        if matched_sym and matched_sym.definitions:
            reaching_def = matched_sym.definitions[-1]
            reaching_def_id = reaching_def.definition_id
            reaching_def.reader_ids.append(read_id)

        read_obj = VarRead(
            read_id=read_id,
            variable_name=clean_name,
            requested_scope=scope_qualifier,
            resolved_scope_id=resolved_scope_id,
            ast_node=ast_node,
            statement_index=stmt_idx,
            reaching_definition_id=reaching_def_id,
            is_uninitialized=is_uninit,
        )

        if matched_sym:
            matched_sym.reads.append(read_obj)
        else:
            # Record uninitialized read symbol in current scope
            placeholder = self.current_scope.define_symbol(clean_name, original_name=clean_name)
            placeholder.is_uninitialized = True
            placeholder.reads.append(read_obj)
            matched_sym = placeholder

        return matched_sym, read_obj

    def resolve_write(
        self,
        var_name: str,
        scope_qualifier: Optional[str] = None,
        value: Any = None,
        value_node: Optional[ASTNode] = None,
        ast_node: Optional[ASTNode] = None,
        stmt_idx: int = 0,
        is_constant: bool = False,
        is_private: bool = False,
        data_type: Optional[str] = None,
    ) -> Tuple[ScopeSymbol, VarDefinition]:
        """
        Records a variable assignment or declaration, detecting scope shadowing.
        """
        clean_name = var_name.lstrip("$").replace("`", "")
        key = clean_name.lower()
        target_frame = self.resolve_target_frame(scope_qualifier)

        if scope_qualifier and scope_qualifier.lower() == "private":
            is_private = True

        # Check shadowing: if unqualified and written locally while outer scope defines it
        is_shadowed = False
        shadowed_id: Optional[int] = None
        if not scope_qualifier or scope_qualifier.lower() in ("local", "private"):
            curr: Optional[ScopeFrame] = target_frame.parent
            while curr is not None:
                outer_sym = curr.get_symbol(key)
                if outer_sym is not None and not outer_sym.is_private:
                    is_shadowed = True
                    shadowed_id = curr.scope_id
                    break
                curr = curr.parent

        sym = target_frame.define_symbol(
            name=clean_name,
            original_name=clean_name,
            is_private=is_private,
            data_type=data_type,
        )
        if is_shadowed:
            sym.is_shadowed = True
            sym.shadowed_scope_id = shadowed_id

        # If previous definition had zero readers, it was overwritten without being read (dead)
        if sym.definitions:
            prev_def = sym.definitions[-1]
            if len(prev_def.reader_ids) == 0:
                prev_def.is_dead = True
                sym.is_dead = True

        def_id = self._next_def_id
        self._next_def_id += 1

        # Infer constant literal value
        const_val = value
        const_node = value_node
        is_const = is_constant

        if const_val is None and value_node is not None:
            if isinstance(value_node, StringLiteralNode):
                const_val = value_node.value
                is_const = True
            elif isinstance(value_node, NumberLiteralNode):
                const_val = value_node.value
                is_const = True

        def_obj = VarDefinition(
            definition_id=def_id,
            variable_name=clean_name,
            scope_type=target_frame.scope_type,
            scope_id=target_frame.scope_id,
            ast_node=ast_node,
            value=const_val,
            is_constant=is_const,
            statement_index=stmt_idx,
            is_dead=False,
        )
        sym.definitions.append(def_obj)

        # Update symbol constant tracking
        if len(sym.definitions) == 1 and is_const:
            sym.is_constant = True
            sym.constant_value = const_val
            sym.constant_node = const_node
        else:
            # Reassigned: no longer guaranteed constant across its lifecycle
            sym.is_constant = False
            sym.constant_value = None
            sym.constant_node = None

        return sym, def_obj

    def remove_variable(self, var_name: str, scope_qualifier: Optional[str] = None) -> bool:
        """Removes a symbol from target scope (implements Remove-Variable / rv)."""
        target_frame = self.resolve_target_frame(scope_qualifier)
        key = var_name.lstrip("$").replace("`", "").lower()
        if key in target_frame.symbols:
            del target_frame.symbols[key]
            return True
        return False

    def clear_variable(self, var_name: str, scope_qualifier: Optional[str] = None) -> bool:
        """Clears a variable value in target scope (implements Clear-Variable / clv)."""
        target_frame = self.resolve_target_frame(scope_qualifier)
        key = var_name.lstrip("$").replace("`", "").lower()
        sym = target_frame.get_symbol(key)
        if sym:
            sym.is_constant = False
            sym.constant_value = None
            sym.constant_node = None
            return True
        return False

    def finalize_analysis(self) -> ScopeAnalysisSummary:
        """
        Sweeps all frames, marks dead assignments, and compiles comprehensive summary telemetry.
        """
        total_symbols = 0
        total_defs = 0
        total_reads = 0
        dead_assignments_count = 0
        shadowed_count = 0
        uninit_reads_count = 0
        const_candidates_count = 0

        scopes_summary: List[Dict[str, Any]] = []
        symbols_table: List[Dict[str, Any]] = []
        dead_assignments: List[Dict[str, Any]] = []
        shadowed_symbols: List[Dict[str, Any]] = []
        uninit_reads: List[Dict[str, Any]] = []
        const_candidates: List[Dict[str, Any]] = []

        for frame_id, frame in sorted(self.all_frames.items()):
            frame_entry = {
                "scope_id": frame.scope_id,
                "scope_type": frame.scope_type.value,
                "name": frame.name,
                "parent_id": frame.parent.scope_id if frame.parent else None,
                "symbols_count": len(frame.symbols),
            }
            scopes_summary.append(frame_entry)

            for sym_name, sym in sorted(frame.symbols.items()):
                total_symbols += 1
                total_defs += len(sym.definitions)
                total_reads += len(sym.reads)

                # Check trailing dead definitions (defined but never read at scope exit)
                for d in sym.definitions:
                    if len(d.reader_ids) == 0:
                        d.is_dead = True
                        sym.is_dead = True
                        dead_assignments_count += 1
                        dead_assignments.append({
                            "definition_id": d.definition_id,
                            "variable": sym.original_name,
                            "scope": frame.name,
                            "statement_index": d.statement_index,
                            "value": str(d.value) if d.value is not None else None,
                        })

                if sym.is_shadowed:
                    shadowed_count += 1
                    shadowed_symbols.append({
                        "variable": sym.original_name,
                        "scope": frame.name,
                        "shadowed_scope_id": sym.shadowed_scope_id,
                    })

                for r in sym.reads:
                    if r.is_uninitialized:
                        uninit_reads_count += 1
                        uninit_reads.append({
                            "read_id": r.read_id,
                            "variable": sym.original_name,
                            "scope": frame.name,
                            "statement_index": r.statement_index,
                        })

                if sym.is_constant and sym.constant_value is not None:
                    const_candidates_count += 1
                    const_candidates.append({
                        "variable": sym.original_name,
                        "scope": frame.name,
                        "value": sym.constant_value,
                        "reads": len(sym.reads),
                    })

                symbols_table.append({
                    "name": sym.original_name,
                    "scope_id": frame.scope_id,
                    "scope": frame.name,
                    "is_constant": sym.is_constant,
                    "constant_value": sym.constant_value,
                    "definitions": len(sym.definitions),
                    "reads": len(sym.reads),
                    "is_shadowed": sym.is_shadowed,
                    "is_dead": any(d.is_dead for d in sym.definitions),
                    "live_range": list(sym.live_range),
                })

        return ScopeAnalysisSummary(
            total_scopes=len(self.all_frames),
            total_symbols=total_symbols,
            total_definitions=total_defs,
            total_reads=total_reads,
            dead_assignments_count=dead_assignments_count,
            shadowed_symbols_count=shadowed_count,
            uninitialized_reads_count=uninit_reads_count,
            constant_candidates_count=const_candidates_count,
            scopes=scopes_summary,
            symbols_table=symbols_table,
            dead_assignments=dead_assignments,
            shadowed_symbols=shadowed_symbols,
            uninitialized_reads=uninit_reads,
            constant_candidates=const_candidates,
        )
