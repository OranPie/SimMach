from __future__ import annotations

from typing import Optional

from simmach.rvprog import Program
from .parser import parse, ParseError
from .lexer import LexError
from .codegen import codegen, CodegenError


__all__ = ["compile", "compile_to_program", "LexError", "ParseError", "CodegenError"]


def compile_to_program(src: str, *, entry_vaddr: int = 0x1000_0000, data_vaddr: int = 0x1000_4000) -> Program:
    """Parse and compile SimScript source into a Program (not yet linked to RVX bytes)."""
    from simmach.rvprog import Program as _Program
    p = _Program(entry=entry_vaddr, text_vaddr=entry_vaddr, data_vaddr=data_vaddr)
    module = parse(src)
    codegen(module, p)
    return p


def compile(src: str, *, entry_vaddr: int = 0x1000_0000, data_vaddr: int = 0x1000_4000) -> bytes:
    """Compile SimScript source to a raw RVX1 executable byte string."""
    p = compile_to_program(src, entry_vaddr=entry_vaddr, data_vaddr=data_vaddr)
    return p.build_rvx()
