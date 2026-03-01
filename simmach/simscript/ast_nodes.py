from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Union


# ── Expressions ─────────────────────────────────────────────────────────────

@dataclass
class IntLit:
    value: int
    line: int = 0

@dataclass
class StrLit:
    value: str   # raw string content (not null-terminated)
    line: int = 0

@dataclass
class Name:
    id: str
    line: int = 0

@dataclass
class BinOp:
    op: str   # "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>",
              # "==", "!=", "<", ">", "<=", ">="
    left: "Expr"
    right: "Expr"
    line: int = 0

@dataclass
class UnaryOp:
    op: str   # "-", "~", "not"
    operand: "Expr"
    line: int = 0

@dataclass
class Call:
    func: str          # name of function (builtin or user-defined)
    args: List["Expr"]
    line: int = 0

Expr = Union[IntLit, StrLit, Name, BinOp, UnaryOp, Call]


# ── Statements ───────────────────────────────────────────────────────────────

@dataclass
class Assign:
    target: str     # variable name
    value: Expr
    line: int = 0

@dataclass
class ExprStmt:
    expr: Expr
    line: int = 0

@dataclass
class Return:
    value: Optional[Expr]
    line: int = 0

@dataclass
class Pass:
    line: int = 0

@dataclass
class Break:
    line: int = 0

@dataclass
class Continue:
    line: int = 0

@dataclass
class If:
    test: Expr
    body: List["Stmt"]
    orelse: List["Stmt"]   # empty if no else
    line: int = 0

@dataclass
class While:
    test: Expr
    body: List["Stmt"]
    line: int = 0

Stmt = Union[Assign, ExprStmt, Return, Pass, Break, Continue, If, While]


# ── Top-level ────────────────────────────────────────────────────────────────

@dataclass
class Const:
    """Module-level compile-time integer constant."""
    name: str
    value: int
    line: int = 0

@dataclass
class FuncDef:
    name: str
    args: List[str]
    body: List[Stmt]
    line: int = 0

@dataclass
class Module:
    consts: List[Const] = field(default_factory=list)
    funcs: List[FuncDef] = field(default_factory=list)
