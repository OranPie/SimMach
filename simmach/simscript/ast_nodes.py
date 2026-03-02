from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Union


# ── Expressions ─────────────────────────────────────────────────────────────

@dataclass(slots=True)
class IntLit:
    value: int
    line: int = 0

@dataclass(slots=True)
class StrLit:
    value: str   # raw string content (not null-terminated)
    line: int = 0

@dataclass(slots=True)
class Name:
    id: str
    line: int = 0

@dataclass(slots=True)
class BinOp:
    op: str   # "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>",
              # "==", "!=", "<", ">", "<=", ">="
    left: "Expr"
    right: "Expr"
    line: int = 0

@dataclass(slots=True)
class UnaryOp:
    op: str   # "-", "~", "not"
    operand: "Expr"
    line: int = 0

@dataclass(slots=True)
class Call:
    func: str          # name of function (builtin or user-defined)
    args: List["Expr"]
    line: int = 0

Expr = Union[IntLit, StrLit, Name, BinOp, UnaryOp, Call]


# ── Statements ───────────────────────────────────────────────────────────────

@dataclass(slots=True)
class Assign:
    target: str     # variable name
    value: Expr
    line: int = 0

@dataclass(slots=True)
class ExprStmt:
    expr: Expr
    line: int = 0

@dataclass(slots=True)
class Return:
    value: Optional[Expr]
    line: int = 0

@dataclass(slots=True)
class Pass:
    line: int = 0

@dataclass(slots=True)
class Break:
    line: int = 0

@dataclass(slots=True)
class Continue:
    line: int = 0

@dataclass(slots=True)
class If:
    test: Expr
    body: List["Stmt"]
    orelse: List["Stmt"]   # empty if no else
    line: int = 0

@dataclass(slots=True)
class While:
    test: Expr
    body: List["Stmt"]
    line: int = 0

Stmt = Union[Assign, ExprStmt, Return, Pass, Break, Continue, If, While]


# ── Top-level ────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class Const:
    """Module-level compile-time integer constant."""
    name: str
    value: int
    line: int = 0

@dataclass(slots=True)
class FuncDef:
    name: str
    args: List[str]
    body: List[Stmt]
    line: int = 0

@dataclass(slots=True)
class Module:
    consts: List[Const] = field(default_factory=list)
    funcs: List[FuncDef] = field(default_factory=list)
