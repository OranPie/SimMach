from __future__ import annotations

from dataclasses import dataclass
from enum import auto, Enum
from typing import Iterator, List


class TT(Enum):
    # Literals
    INT    = auto()
    STRING = auto()
    IDENT  = auto()
    # Keywords
    DEF    = auto()
    IF     = auto()
    ELIF   = auto()
    ELSE   = auto()
    WHILE  = auto()
    RETURN = auto()
    PASS   = auto()
    BREAK  = auto()
    CONTINUE = auto()
    AND    = auto()
    OR     = auto()
    NOT    = auto()
    # Operators
    PLUS   = auto()
    MINUS  = auto()
    STAR   = auto()
    SLASH  = auto()
    PERCENT= auto()
    AMP    = auto()
    PIPE   = auto()
    CARET  = auto()
    SHL    = auto()
    SHR    = auto()
    EQ     = auto()   # ==
    NEQ    = auto()   # !=
    LT     = auto()
    GT     = auto()
    LEQ    = auto()
    GEQ    = auto()
    ASSIGN = auto()   # =
    TILDE  = auto()   # ~
    # Punctuation
    LPAREN = auto()
    RPAREN = auto()
    COMMA  = auto()
    COLON  = auto()
    # Layout
    NEWLINE= auto()
    INDENT = auto()
    DEDENT = auto()
    EOF    = auto()


_KEYWORDS = {
    "def": TT.DEF, "if": TT.IF, "elif": TT.ELIF, "else": TT.ELSE,
    "while": TT.WHILE, "return": TT.RETURN, "pass": TT.PASS,
    "break": TT.BREAK, "continue": TT.CONTINUE,
    "and": TT.AND, "or": TT.OR, "not": TT.NOT,
}


@dataclass(frozen=True)
class Token:
    type: TT
    value: object  # int | str | None
    line: int


class LexError(Exception):
    pass


def lex(src: str) -> List[Token]:
    tokens: List[Token] = []
    lines = src.splitlines(keepends=True)
    indent_stack = [0]
    pending_newline = False

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n").rstrip("\r")

        # Blank lines / comment-only lines: emit nothing (no NEWLINE either)
        stripped = line.lstrip()
        if stripped == "" or stripped.startswith("#"):
            continue

        # Measure indentation
        col = 0
        while col < len(line) and line[col] in " \t":
            col += 1
        indent = col

        # Emit NEWLINE for the previous logical line
        if pending_newline:
            tokens.append(Token(TT.NEWLINE, None, lineno - 1))

        # Handle indent/dedent
        if indent > indent_stack[-1]:
            indent_stack.append(indent)
            tokens.append(Token(TT.INDENT, None, lineno))
        else:
            while indent < indent_stack[-1]:
                indent_stack.pop()
                tokens.append(Token(TT.DEDENT, None, lineno))
            if indent != indent_stack[-1]:
                raise LexError(f"line {lineno}: indentation mismatch")

        # Tokenise the rest of the line
        i = col
        while i < len(line):
            c = line[i]

            # Skip whitespace
            if c in " \t":
                i += 1
                continue

            # Comment
            if c == "#":
                break

            # Integer literal (decimal or 0x hex)
            if c.isdigit() or (c == "0" and i + 1 < len(line) and line[i + 1] in "xX"):
                j = i
                if c == "0" and i + 1 < len(line) and line[i + 1] in "xX":
                    i += 2
                    while i < len(line) and (line[i].isdigit() or line[i] in "abcdefABCDEF_"):
                        i += 1
                    tokens.append(Token(TT.INT, int(line[j:i].replace("_", ""), 16), lineno))
                else:
                    while i < len(line) and (line[i].isdigit() or line[i] == "_"):
                        i += 1
                    tokens.append(Token(TT.INT, int(line[j:i].replace("_", "")), lineno))
                continue

            # Negative integer literal (-42)
            if c == "-" and i + 1 < len(line) and line[i + 1].isdigit():
                # Only treat as negative literal if previous token is not a value
                prev = tokens[-1].type if tokens else None
                if prev not in (TT.INT, TT.STRING, TT.IDENT, TT.RPAREN):
                    j = i
                    i += 1
                    while i < len(line) and (line[i].isdigit() or line[i] == "_"):
                        i += 1
                    tokens.append(Token(TT.INT, int(line[j:i].replace("_", "")), lineno))
                    continue

            # String literal
            if c in ('"', "'"):
                q = c
                i += 1
                s = []
                while i < len(line):
                    ch = line[i]
                    if ch == "\\":
                        i += 1
                        esc = line[i] if i < len(line) else ""
                        s.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\",
                                  '"': '"', "'": "'"}.get(esc, "\\" + esc))
                    elif ch == q:
                        i += 1
                        break
                    else:
                        s.append(ch)
                    i += 1
                tokens.append(Token(TT.STRING, "".join(s), lineno))
                continue

            # Identifier / keyword
            if c.isalpha() or c == "_":
                j = i
                while i < len(line) and (line[i].isalnum() or line[i] == "_"):
                    i += 1
                word = line[j:i]
                tt = _KEYWORDS.get(word, TT.IDENT)
                tokens.append(Token(tt, word if tt == TT.IDENT else None, lineno))
                continue

            # Two-char operators
            two = line[i:i + 2]
            if two == "==": tokens.append(Token(TT.EQ,    None, lineno)); i += 2; continue
            if two == "!=": tokens.append(Token(TT.NEQ,   None, lineno)); i += 2; continue
            if two == "<=": tokens.append(Token(TT.LEQ,   None, lineno)); i += 2; continue
            if two == ">=": tokens.append(Token(TT.GEQ,   None, lineno)); i += 2; continue
            if two == "<<": tokens.append(Token(TT.SHL,   None, lineno)); i += 2; continue
            if two == ">>": tokens.append(Token(TT.SHR,   None, lineno)); i += 2; continue

            # Single-char
            ONE = {
                "+": TT.PLUS, "-": TT.MINUS, "*": TT.STAR, "/": TT.SLASH,
                "%": TT.PERCENT, "&": TT.AMP, "|": TT.PIPE, "^": TT.CARET,
                "~": TT.TILDE, "=": TT.ASSIGN, "<": TT.LT, ">": TT.GT,
                "(": TT.LPAREN, ")": TT.RPAREN, ",": TT.COMMA, ":": TT.COLON,
            }
            if c in ONE:
                tokens.append(Token(ONE[c], None, lineno))
                i += 1
                continue

            raise LexError(f"line {lineno}: unexpected character {c!r}")

        pending_newline = True

    # Close off final line
    if pending_newline:
        tokens.append(Token(TT.NEWLINE, None, len(lines)))

    # Close remaining indents
    while len(indent_stack) > 1:
        indent_stack.pop()
        tokens.append(Token(TT.DEDENT, None, len(lines)))

    tokens.append(Token(TT.EOF, None, len(lines) + 1))
    return tokens
