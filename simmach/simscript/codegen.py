from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from simmach import rvasm
from simmach.rvprog import Program
from .ast_nodes import (
    Assign, BinOp, Break, Call, Continue, Const, Expr, ExprStmt,
    FuncDef, If, IntLit, Module, Name, Pass, Return, StrLit, Stmt,
    UnaryOp, While,
)
from .builtins import BUILTINS, emit_println
from .regalloc import A0, A1, A2, A3, A4, A5, A6, A7, RA, SP, ZERO, RegAlloc, T_REGS, S_REGS, collect_vars


class CodegenError(Exception):
    pass


# ── Constant-fold a binary op on two known integers ─────────────────────────

def _fold_const(op: str, l: int, r: int) -> Optional[int]:
    try:
        if op == "+":  return l + r
        if op == "-":  return l - r
        if op == "*":  return l * r
        if op == "/":  return l // r if r else None
        if op == "%":  return l % r  if r else None
        if op == "&":  return l & r
        if op == "|":  return l | r
        if op == "^":  return l ^ r
        if op == "<<": return l << (r & 63)
        if op == ">>": return l >> (r & 63)
        if op == "==": return int(l == r)
        if op == "!=": return int(l != r)
        if op == "<":  return int(l <  r)
        if op == ">":  return int(l >  r)
        if op == "<=": return int(l <= r)
        if op == ">=": return int(l >= r)
    except Exception:
        pass
    return None


# ── Binary operations → RV64 instructions ───────────────────────────────────

def _emit_binop(p: Program, op: str, dst: int, lhs: int, rhs: int) -> None:
    if op == "+":    p.emit(rvasm.add(dst, lhs, rhs))
    elif op == "-":  p.emit(rvasm.sub(dst, lhs, rhs))
    elif op == "*":  p.emit(rvasm.mul(dst, lhs, rhs))
    elif op == "/":  p.emit(rvasm.div(dst, lhs, rhs))
    elif op == "%":  p.emit(rvasm.rem(dst, lhs, rhs))
    elif op == "&":  p.emit(rvasm.and_(dst, lhs, rhs))
    elif op == "|":  p.emit(rvasm.or_(dst, lhs, rhs))
    elif op == "^":  p.emit(rvasm.xor(dst, lhs, rhs))
    elif op == "<<": p.emit(rvasm.sll(dst, lhs, rhs))
    elif op == ">>": p.emit(rvasm.srl(dst, lhs, rhs))
    elif op == "==":
        p.emit(rvasm.sub(dst, lhs, rhs))
        p.emit(rvasm.seqz(dst, dst))
    elif op == "!=":
        p.emit(rvasm.sub(dst, lhs, rhs))
        p.emit(rvasm.snez(dst, dst))
    elif op == "<":  p.emit(rvasm.slt(dst, lhs, rhs))
    elif op == ">":  p.emit(rvasm.slt(dst, rhs, lhs))
    elif op == "<=":
        p.emit(rvasm.slt(dst, rhs, lhs))
        p.emit(rvasm.xori(dst, dst, 1))
    elif op == ">=":
        p.emit(rvasm.slt(dst, lhs, rhs))
        p.emit(rvasm.xori(dst, dst, 1))
    elif op == "and":
        p.emit(rvasm.and_(dst, lhs, rhs))
    elif op == "or":
        p.emit(rvasm.or_(dst, lhs, rhs))
    else:
        raise CodegenError(f"unknown binop {op!r}")


# ── Per-function code generator ──────────────────────────────────────────────

class FuncGen:
    def __init__(
        self,
        p: Program,
        func: FuncDef,
        user_funcs: Dict[str, FuncDef],
        global_consts: Dict[str, int],
        string_cache: Dict[str, int],
    ) -> None:
        self.p = p
        self.func = func
        self.user_funcs = user_funcs
        self.global_consts = global_consts
        self.string_cache = string_cache
        self.ra = RegAlloc()
        self._label_counter = [0]
        self._loop_stack: List[Tuple[str, str]] = []  # (loop_label, end_label)

        for v in collect_vars(func):
            self.ra.alloc_var(v)

    def _fresh_label(self, prefix: str) -> str:
        n = self._label_counter[0]
        self._label_counter[0] += 1
        return f"{self.func.name}_{prefix}_{n}"

    # ── Variable load/store helpers ──────────────────────────────────────────

    def _load_var(self, name: str, dest: int) -> None:
        reg = self.ra.get_var_reg(name)
        if reg is not None:
            if reg != dest:
                self.p.emit(rvasm.addi(dest, reg, 0))
        else:
            slot = self.ra.get_spill_slot(name)
            if slot is None:
                raise CodegenError(f"undefined variable {name!r}")
            off = self._spill_base_off() + slot * 8
            self.p.emit(rvasm.ld(dest, SP, off))

    def _store_var(self, name: str, src: int) -> None:
        reg = self.ra.get_var_reg(name)
        if reg is not None:
            if reg != src:
                self.p.emit(rvasm.addi(reg, src, 0))
        else:
            slot = self.ra.get_spill_slot(name)
            if slot is None:
                raise CodegenError(f"undefined variable {name!r}")
            off = self._spill_base_off() + slot * 8
            self.p.emit(rvasm.sd(src, SP, off))

    def _frame_size(self) -> int:
        saved = 1 + len(self.ra.used_s_regs())
        total_slots = saved + self.ra.spill_count()
        size = total_slots * 8
        return (size + 15) & ~15

    def _spill_base_off(self) -> int:
        return (1 + len(self.ra.used_s_regs())) * 8

    # ── Prologue / epilogue ──────────────────────────────────────────────────

    def _emit_prologue(self) -> None:
        fs = self._frame_size()
        p = self.p
        p.emit(rvasm.addi(SP, SP, -fs))
        p.emit(rvasm.sd(RA, SP, 0))
        for i, reg in enumerate(self.ra.used_s_regs()):
            p.emit(rvasm.sd(reg, SP, (i + 1) * 8))
        for i, arg in enumerate(self.func.args):
            if i >= 6:
                raise CodegenError("more than 6 function arguments not supported")
            src_reg = A0 + i
            dest_reg = self.ra.get_var_reg(arg)
            if dest_reg is not None:
                if dest_reg != src_reg:
                    p.emit(rvasm.addi(dest_reg, src_reg, 0))
            else:
                slot = self.ra.get_spill_slot(arg)
                off = self._spill_base_off() + slot * 8  # type: ignore[operator]
                p.emit(rvasm.sd(src_reg, SP, off))

    def _emit_epilogue(self) -> None:
        fs = self._frame_size()
        p = self.p
        for i, reg in enumerate(self.ra.used_s_regs()):
            p.emit(rvasm.ld(reg, SP, (i + 1) * 8))
        p.emit(rvasm.ld(RA, SP, 0))
        p.emit(rvasm.addi(SP, SP, fs))
        p.emit(rvasm.jalr(0, RA, 0))

    # ── Constant evaluation of an expression ────────────────────────────────

    def _try_const_eval(self, expr: Expr) -> Optional[int]:
        if isinstance(expr, IntLit):
            return expr.value
        if isinstance(expr, Name) and expr.id in self.global_consts:
            return self.global_consts[expr.id]
        if isinstance(expr, UnaryOp):
            v = self._try_const_eval(expr.operand)
            if v is None:
                return None
            if expr.op == "-": return -v
            if expr.op == "~": return ~v
        if isinstance(expr, BinOp):
            l = self._try_const_eval(expr.left)
            r = self._try_const_eval(expr.right)
            if l is not None and r is not None:
                return _fold_const(expr.op, l, r)
        return None

    # ── Expression emission — returns register holding the result ────────────

    def emit_expr(self, expr: Expr) -> int:
        p = self.p
        ra = self.ra

        # Constant folding: entire expression is a compile-time constant
        cv = self._try_const_eval(expr)
        if cv is not None:
            if cv == 0:
                return ZERO  # x0 is always 0 — no instruction needed
            t = ra.next_temp()
            p.li(t, cv)
            return t

        if isinstance(expr, StrLit):
            encoded = expr.value.encode("utf-8") + b"\x00"
            # String interning: same bytes → same data segment address
            key = expr.value
            if key in self.string_cache:
                addr = self.string_cache[key]
            else:
                p.align_data(8)
                addr = p.db(encoded)
                self.string_cache[key] = addr
            t = ra.next_temp()
            p.li(t, addr)
            return t

        if isinstance(expr, Name):
            # Global const was already handled by _try_const_eval above,
            # so this is a mutable local variable.
            t = ra.next_temp()
            self._load_var(expr.id, t)
            return t

        if isinstance(expr, UnaryOp):
            operand_reg = self.emit_expr(expr.operand)
            t = ra.next_temp()
            if expr.op == "-":
                p.emit(rvasm.sub(t, ZERO, operand_reg))
            elif expr.op == "~":
                p.emit(rvasm.xori(t, operand_reg, -1))
            elif expr.op == "not":
                p.emit(rvasm.seqz(t, operand_reg))
            return t

        if isinstance(expr, BinOp):
            # Partial constant folding: if one side is constant, fold if possible
            lhs = self.emit_expr(expr.left)
            rhs = self.emit_expr(expr.right)
            t = ra.next_temp()
            _emit_binop(p, expr.op, t, lhs, rhs)
            return t

        if isinstance(expr, Call):
            return self._emit_call(expr)

        raise CodegenError(f"unknown expr type {type(expr).__name__}")

    # ── Optimized branch emission ────────────────────────────────────────────

    def emit_branch_if_false(self, expr: Expr, label: str) -> None:
        """Emit branch to *label* when *expr* evaluates to false/0."""
        p = self.p

        # Constant: always/never branch
        cv = self._try_const_eval(expr)
        if cv is not None:
            if cv == 0:
                p.jal(0, label)   # always branch
            # else: never branch — emit nothing
            return

        if isinstance(expr, BinOp):
            op = expr.op
            # short-circuit and: jump if either side is false
            if op == "and":
                self.emit_branch_if_false(expr.left, label)
                self.emit_branch_if_false(expr.right, label)
                return
            # short-circuit or: jump if BOTH sides are false
            if op == "or":
                skip = self._fresh_label("or_skip")
                self.emit_branch_if_true(expr.left, skip)
                self.emit_branch_if_false(expr.right, label)
                p.label(skip)
                return
            # Comparison → direct branch instruction (no sub+seqz overhead)
            lv = self._try_const_eval(expr.left)
            rv = self._try_const_eval(expr.right)
            if lv is None and rv is None:
                lhs = self.emit_expr(expr.left)
                rhs = self.emit_expr(expr.right)
                if op == "==": p.bne(lhs, rhs, label); return
                if op == "!=": p.beq(lhs, rhs, label); return
                if op == "<":  p.bge(lhs, rhs, label); return
                if op == ">":  p.bge(rhs, lhs, label); return
                if op == "<=":
                    p.blt(rhs, lhs, label); return   # NOT(l <= r) = l > r = r < l
                if op == ">=":
                    p.blt(lhs, rhs, label); return   # NOT(l >= r) = l < r

        # Fallback: evaluate and branch on zero
        self.ra.reset_temps()
        cond = self.emit_expr(expr)
        p.beq(cond, ZERO, label)

    def emit_branch_if_true(self, expr: Expr, label: str) -> None:
        """Emit branch to *label* when *expr* evaluates to true/non-zero."""
        p = self.p

        cv = self._try_const_eval(expr)
        if cv is not None:
            if cv != 0:
                p.jal(0, label)
            return

        if isinstance(expr, BinOp):
            op = expr.op
            if op == "or":
                self.emit_branch_if_true(expr.left, label)
                self.emit_branch_if_true(expr.right, label)
                return
            if op == "and":
                skip = self._fresh_label("and_skip")
                self.emit_branch_if_false(expr.left, skip)
                self.emit_branch_if_true(expr.right, label)
                p.label(skip)
                return
            lv = self._try_const_eval(expr.left)
            rv = self._try_const_eval(expr.right)
            if lv is None and rv is None:
                lhs = self.emit_expr(expr.left)
                rhs = self.emit_expr(expr.right)
                if op == "==": p.beq(lhs, rhs, label); return
                if op == "!=": p.bne(lhs, rhs, label); return
                if op == "<":  p.blt(lhs, rhs, label); return
                if op == ">":  p.blt(rhs, lhs, label); return
                if op == "<=":
                    p.bge(rhs, lhs, label); return
                if op == ">=":
                    p.bge(lhs, rhs, label); return

        self.ra.reset_temps()
        cond = self.emit_expr(expr)
        p.bne(cond, ZERO, label)

    def _emit_call(self, call: Call) -> int:
        p = self.p
        ra = self.ra

        arg_regs = [self.emit_expr(a) for a in call.args]
        dest = ra.next_temp()

        if call.func in BUILTINS:
            emit_fn, expected = BUILTINS[call.func]
            if call.func == "println":
                if len(call.args) != 1 or not isinstance(call.args[0], StrLit):
                    raise CodegenError("println() requires a single string literal")
                str_len = len(call.args[0].value.encode("utf-8"))
                emit_println(p, arg_regs, dest, str_len)
            elif call.func == "write" and len(call.args) == 2 and isinstance(call.args[1], StrLit):
                str_len = len(call.args[1].value.encode("utf-8"))
                len_reg = ra.next_temp()
                p.li(len_reg, str_len)
                emit_fn(p, arg_regs + [len_reg], dest)
            else:
                if expected != len(call.args):
                    raise CodegenError(
                        f"{call.func}() expects {expected} args, got {len(call.args)}"
                    )
                emit_fn(p, arg_regs, dest)
            return dest

        if call.func not in self.user_funcs:
            raise CodegenError(f"undefined function {call.func!r}")
        if len(call.args) > 6:
            raise CodegenError("more than 6 arguments not supported")
        for i, ar in enumerate(reversed(arg_regs)):
            p.emit(rvasm.addi(A0 + (len(arg_regs) - 1 - i), ar, 0))
        p.jal(RA, call.func)
        if dest != A0:
            p.emit(rvasm.addi(dest, A0, 0))
        return dest

    # ── Statement emission ───────────────────────────────────────────────────

    def emit_stmt(self, stmt: Stmt) -> None:
        self.ra.reset_temps()

        if isinstance(stmt, Pass):
            return

        if isinstance(stmt, Break):
            if not self._loop_stack:
                raise CodegenError("'break' outside loop")
            _, end_label = self._loop_stack[-1]
            self.p.jal(0, end_label)
            return

        if isinstance(stmt, Continue):
            if not self._loop_stack:
                raise CodegenError("'continue' outside loop")
            loop_label, _ = self._loop_stack[-1]
            self.p.jal(0, loop_label)
            return

        if isinstance(stmt, Assign):
            val_reg = self.emit_expr(stmt.value)
            self._store_var(stmt.target, val_reg)
            return

        if isinstance(stmt, ExprStmt):
            self.emit_expr(stmt.expr)
            return

        if isinstance(stmt, Return):
            if stmt.value is not None:
                val_reg = self.emit_expr(stmt.value)
                if val_reg != A0:
                    self.p.emit(rvasm.addi(A0, val_reg, 0))
            self._emit_epilogue()
            return

        if isinstance(stmt, If):
            self._emit_if(stmt)
            return

        if isinstance(stmt, While):
            self._emit_while(stmt)
            return

        raise CodegenError(f"unknown stmt type {type(stmt).__name__}")

    def _emit_if(self, stmt: If) -> None:
        p = self.p
        label_else = self._fresh_label("else")
        label_end  = self._fresh_label("end")

        self.ra.reset_temps()
        target = label_else if stmt.orelse else label_end
        self.emit_branch_if_false(stmt.test, target)

        for s in stmt.body:
            self.emit_stmt(s)

        if stmt.orelse:
            p.jal(0, label_end)
            p.label(label_else)
            for s in stmt.orelse:
                self.emit_stmt(s)

        p.label(label_end)

    def _emit_while(self, stmt: While) -> None:
        p = self.p
        label_loop = self._fresh_label("loop")
        label_end  = self._fresh_label("endloop")

        self._loop_stack.append((label_loop, label_end))
        p.label(label_loop)
        self.ra.reset_temps()
        self.emit_branch_if_false(stmt.test, label_end)

        for s in stmt.body:
            self.emit_stmt(s)

        p.jal(0, label_loop)
        p.label(label_end)
        self._loop_stack.pop()

    # ── Top-level function emit ──────────────────────────────────────────────

    def emit(self) -> None:
        self.p.label(self.func.name)
        self._emit_prologue()
        for stmt in self.func.body:
            self.emit_stmt(stmt)
        self.p.emit(rvasm.addi(A0, ZERO, 0))
        self._emit_epilogue()


# ── Module-level codegen ──────────────────────────────────────────────────────

def codegen(module: Module, p: Optional[Program] = None) -> Program:
    if p is None:
        entry_vaddr = 0x1000_0000
        p = Program(entry=entry_vaddr, text_vaddr=entry_vaddr, data_vaddr=0x1000_4000)

    # Build global constants dict
    global_consts: Dict[str, int] = {c.name: c.value for c in module.consts}

    # Shared string cache across all functions
    string_cache: Dict[str, int] = {}

    user_funcs: Dict[str, FuncDef] = {f.name: f for f in module.funcs}

    entry_func = user_funcs.get("main") or module.funcs[0]

    p.label("_start")
    if entry_func.name != "_start":
        p.emit(rvasm.addi(A0, 0, 0))
        p.jal(RA, entry_func.name)
        from constants import Sysno
        p.li(A7, int(Sysno.EXIT))
        p.emit(rvasm.ecall())

    for func in module.funcs:
        fg = FuncGen(p, func, user_funcs, global_consts, string_cache)
        fg.emit()

    return p

