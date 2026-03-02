from __future__ import annotations

from typing import List, Optional

from .lexer import lex, Token, TT
from .ast_nodes import (
    Assign, BinOp, Break, Call, Const, Continue, Expr, ExprStmt, FuncDef,
    If, IntLit, Module, Name, Pass, Return, StrLit, Stmt, UnaryOp, While,
)


class ParseError(Exception):
    pass


class Parser:
    def __init__(self, tokens: List[Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    # ── Token navigation ────────────────────────────────────────────────────

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        if tok.type != TT.EOF:
            self._pos += 1
        return tok

    def _check(self, *types: TT) -> bool:
        return self._peek().type in types

    def _match(self, *types: TT) -> Optional[Token]:
        if self._check(*types):
            return self._advance()
        return None

    def _expect(self, tt: TT) -> Token:
        tok = self._peek()
        if tok.type != tt:
            raise ParseError(f"line {tok.line}: expected {tt.name}, got {tok.type.name!r} ({tok.value!r})")
        return self._advance()

    def _skip_newlines(self) -> None:
        while self._check(TT.NEWLINE):
            self._advance()

    # ── Top level ────────────────────────────────────────────────────────────

    def parse(self) -> Module:
        self._skip_newlines()
        consts: List[Const] = []
        const_env: dict[str, int] = {}
        funcs: List[FuncDef] = []
        while not self._check(TT.EOF):
            self._skip_newlines()
            if self._check(TT.EOF):
                break
            if self._check(TT.DEF):
                funcs.append(self._parse_funcdef())
            elif (self._check(TT.IDENT) and
                  self._pos + 1 < len(self._tokens) and
                  self._tokens[self._pos + 1].type == TT.ASSIGN):
                # Module-level constant: NAME = integer_expr
                name_tok = self._advance()
                self._advance()  # ASSIGN
                val_expr = self._parse_expr()
                self._match(TT.NEWLINE)
                v = self._const_eval(val_expr, const_env)
                if v is None:
                    raise ParseError(f"line {name_tok.line}: module constant must be an integer expression")
                name = str(name_tok.value)
                consts.append(Const(name=name, value=v, line=name_tok.line))
                const_env[name] = v
            else:
                raise ParseError(f"line {self._peek().line}: expected 'def' or constant at module level")
        return Module(consts=consts, funcs=funcs)

    def _const_eval(self, expr: Expr, env: dict[str, int]) -> Optional[int]:
        """Evaluate a constant expression at parse time."""
        if isinstance(expr, IntLit):
            return expr.value
        if isinstance(expr, Name) and expr.id in env:
            return env[expr.id]
        if isinstance(expr, UnaryOp):
            v = self._const_eval(expr.operand, env)
            if v is None:
                return None
            if expr.op == "-": return -v
            if expr.op == "~": return ~v
        if isinstance(expr, BinOp):
            l = self._const_eval(expr.left, env)
            r = self._const_eval(expr.right, env)
            if l is None or r is None:
                return None
            if expr.op == "+": return l + r
            if expr.op == "-": return l - r
            if expr.op == "*": return l * r
            if expr.op == "&": return l & r
            if expr.op == "|": return l | r
            if expr.op == "^": return l ^ r
            if expr.op == "<<": return l << (r & 63)
            if expr.op == ">>": return l >> (r & 63)
            if expr.op == "/": return l // r if r else 0
            if expr.op == "%": return l % r if r else 0
        return None

    def _parse_funcdef(self) -> FuncDef:
        tok = self._expect(TT.DEF)
        name_tok = self._expect(TT.IDENT)
        self._expect(TT.LPAREN)
        args: List[str] = []
        while not self._check(TT.RPAREN):
            args.append(self._expect(TT.IDENT).value)  # type: ignore[arg-type]
            if not self._match(TT.COMMA):
                break
        self._expect(TT.RPAREN)
        self._expect(TT.COLON)
        self._expect(TT.NEWLINE)
        body = self._parse_block()
        return FuncDef(name=name_tok.value, args=args, body=body, line=tok.line)  # type: ignore[arg-type]

    # ── Block ────────────────────────────────────────────────────────────────

    def _parse_block(self) -> List[Stmt]:
        self._expect(TT.INDENT)
        stmts: List[Stmt] = []
        while not self._check(TT.DEDENT, TT.EOF):
            self._skip_newlines()
            if self._check(TT.DEDENT, TT.EOF):
                break
            stmts.append(self._parse_stmt())
        self._match(TT.DEDENT)
        return stmts

    # ── Statements ───────────────────────────────────────────────────────────

    def _parse_stmt(self) -> Stmt:
        tok = self._peek()

        if tok.type == TT.IF:
            return self._parse_if()
        if tok.type == TT.WHILE:
            return self._parse_while()
        if tok.type == TT.RETURN:
            return self._parse_return()
        if tok.type == TT.PASS:
            self._advance()
            self._match(TT.NEWLINE)
            return Pass(line=tok.line)
        if tok.type == TT.BREAK:
            self._advance()
            self._match(TT.NEWLINE)
            return Break(line=tok.line)
        if tok.type == TT.CONTINUE:
            self._advance()
            self._match(TT.NEWLINE)
            return Continue(line=tok.line)

        # Assignment or expression statement
        # Lookahead: IDENT ASSIGN → assignment
        if tok.type == TT.IDENT and self._pos + 1 < len(self._tokens) and self._tokens[self._pos + 1].type == TT.ASSIGN:
            name = self._advance().value  # IDENT
            self._advance()              # ASSIGN
            val = self._parse_expr()
            self._match(TT.NEWLINE)
            return Assign(target=name, value=val, line=tok.line)  # type: ignore[arg-type]

        expr = self._parse_expr()
        self._match(TT.NEWLINE)
        return ExprStmt(expr=expr, line=tok.line)

    def _parse_if(self) -> If:
        tok = self._expect(TT.IF)
        test = self._parse_expr()
        self._expect(TT.COLON)
        self._expect(TT.NEWLINE)
        body = self._parse_block()
        orelse = self._parse_elif_or_else()
        return If(test=test, body=body, orelse=orelse, line=tok.line)

    def _parse_elif_or_else(self) -> List[Stmt]:
        """Parse optional elif chain and/or else block."""
        if self._check(TT.ELIF):
            tok = self._advance()
            test = self._parse_expr()
            self._expect(TT.COLON)
            self._expect(TT.NEWLINE)
            body = self._parse_block()
            orelse = self._parse_elif_or_else()
            return [If(test=test, body=body, orelse=orelse, line=tok.line)]
        if self._check(TT.ELSE):
            self._advance()
            self._expect(TT.COLON)
            self._expect(TT.NEWLINE)
            return self._parse_block()
        return []

    def _parse_while(self) -> While:
        tok = self._expect(TT.WHILE)
        test = self._parse_expr()
        self._expect(TT.COLON)
        self._expect(TT.NEWLINE)
        body = self._parse_block()
        return While(test=test, body=body, line=tok.line)

    def _parse_return(self) -> Return:
        tok = self._expect(TT.RETURN)
        if self._check(TT.NEWLINE, TT.EOF, TT.DEDENT):
            self._match(TT.NEWLINE)
            return Return(value=None, line=tok.line)
        val = self._parse_expr()
        self._match(TT.NEWLINE)
        return Return(value=val, line=tok.line)

    # ── Expressions (Pratt / precedence climbing) ───────────────────────────

    def _parse_expr(self) -> Expr:
        return self._parse_or()

    def _parse_or(self) -> Expr:
        left = self._parse_and()
        while self._check(TT.OR):
            tok = self._advance()
            right = self._parse_and()
            left = BinOp(op="or", left=left, right=right, line=tok.line)
        return left

    def _parse_and(self) -> Expr:
        left = self._parse_not()
        while self._check(TT.AND):
            tok = self._advance()
            right = self._parse_not()
            left = BinOp(op="and", left=left, right=right, line=tok.line)
        return left

    def _parse_not(self) -> Expr:
        if self._check(TT.NOT):
            tok = self._advance()
            return UnaryOp(op="not", operand=self._parse_not(), line=tok.line)
        return self._parse_compare()

    def _parse_compare(self) -> Expr:
        left = self._parse_bitor()
        CMPOPS = {TT.EQ: "==", TT.NEQ: "!=", TT.LT: "<", TT.GT: ">", TT.LEQ: "<=", TT.GEQ: ">="}
        while self._peek().type in CMPOPS:
            tok = self._advance()
            right = self._parse_bitor()
            left = BinOp(op=CMPOPS[tok.type], left=left, right=right, line=tok.line)
        return left

    def _parse_bitor(self) -> Expr:
        left = self._parse_bitxor()
        while self._check(TT.PIPE):
            tok = self._advance()
            right = self._parse_bitxor()
            left = BinOp(op="|", left=left, right=right, line=tok.line)
        return left

    def _parse_bitxor(self) -> Expr:
        left = self._parse_bitand()
        while self._check(TT.CARET):
            tok = self._advance()
            right = self._parse_bitand()
            left = BinOp(op="^", left=left, right=right, line=tok.line)
        return left

    def _parse_bitand(self) -> Expr:
        left = self._parse_shift()
        while self._check(TT.AMP):
            tok = self._advance()
            right = self._parse_shift()
            left = BinOp(op="&", left=left, right=right, line=tok.line)
        return left

    def _parse_shift(self) -> Expr:
        left = self._parse_add()
        while self._check(TT.SHL, TT.SHR):
            tok = self._advance()
            right = self._parse_add()
            op = "<<" if tok.type == TT.SHL else ">>"
            left = BinOp(op=op, left=left, right=right, line=tok.line)
        return left

    def _parse_add(self) -> Expr:
        left = self._parse_mul()
        while self._check(TT.PLUS, TT.MINUS):
            tok = self._advance()
            right = self._parse_mul()
            op = "+" if tok.type == TT.PLUS else "-"
            left = BinOp(op=op, left=left, right=right, line=tok.line)
        return left

    def _parse_mul(self) -> Expr:
        left = self._parse_unary()
        while self._check(TT.STAR, TT.SLASH, TT.PERCENT):
            tok = self._advance()
            right = self._parse_unary()
            op = {TT.STAR: "*", TT.SLASH: "/", TT.PERCENT: "%"}[tok.type]
            left = BinOp(op=op, left=left, right=right, line=tok.line)
        return left

    def _parse_unary(self) -> Expr:
        if self._check(TT.MINUS):
            tok = self._advance()
            return UnaryOp(op="-", operand=self._parse_unary(), line=tok.line)
        if self._check(TT.TILDE):
            tok = self._advance()
            return UnaryOp(op="~", operand=self._parse_unary(), line=tok.line)
        return self._parse_primary()

    def _parse_primary(self) -> Expr:
        tok = self._peek()

        if tok.type == TT.INT:
            self._advance()
            return IntLit(value=tok.value, line=tok.line)  # type: ignore[arg-type]

        if tok.type == TT.STRING:
            self._advance()
            return StrLit(value=tok.value, line=tok.line)  # type: ignore[arg-type]

        if tok.type == TT.LPAREN:
            self._advance()
            expr = self._parse_expr()
            self._expect(TT.RPAREN)
            return expr

        if tok.type == TT.IDENT:
            self._advance()
            # Function call?
            if self._check(TT.LPAREN):
                self._advance()
                args: List[Expr] = []
                while not self._check(TT.RPAREN, TT.EOF):
                    args.append(self._parse_expr())
                    if not self._match(TT.COMMA):
                        break
                self._expect(TT.RPAREN)
                return Call(func=tok.value, args=args, line=tok.line)  # type: ignore[arg-type]
            return Name(id=tok.value, line=tok.line)  # type: ignore[arg-type]

        raise ParseError(f"line {tok.line}: unexpected token {tok.type.name!r} ({tok.value!r})")


def parse(src: str) -> Module:
    tokens = lex(src)
    return Parser(tokens).parse()
