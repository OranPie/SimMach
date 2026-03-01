from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# RISC-V register numbers
# Callee-saved (preserved across calls) → used for named variables
S_REGS = [8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]   # s0-s11

# Caller-saved temporaries → used for sub-expression results
T_REGS = [5, 6, 7, 28, 29, 30, 31]                          # t0-t6

# Argument / return registers
A_REGS = [10, 11, 12, 13, 14, 15, 16, 17]                  # a0-a7 (a7=syscall#)

A0, A1, A2, A3, A4, A5, A6, A7 = A_REGS
RA = 1
SP = 2
ZERO = 0


@dataclass
class RegAlloc:
    """
    Maps named variables to callee-saved registers for a single function scope.
    Provides a simple temp-register stack for sub-expression evaluation.
    """
    _var_to_reg: Dict[str, int] = field(default_factory=dict)
    _spill_slots: Dict[str, int] = field(default_factory=dict)  # var → stack slot index
    _spill_count: int = 0
    _used_s_regs: List[int] = field(default_factory=list)      # s-regs actually allocated

    def alloc_var(self, name: str) -> None:
        """Declare a variable. Allocates a register or spill slot."""
        if name in self._var_to_reg or name in self._spill_slots:
            return
        # Find a free s-reg
        used = set(self._var_to_reg.values())
        for reg in S_REGS:
            if reg not in used:
                self._var_to_reg[name] = reg
                if reg not in self._used_s_regs:
                    self._used_s_regs.append(reg)
                return
        # Spill to stack
        self._spill_slots[name] = self._spill_count
        self._spill_count += 1

    def get_var_reg(self, name: str) -> Optional[int]:
        """Return register for variable, or None if spilled."""
        return self._var_to_reg.get(name)

    def get_spill_slot(self, name: str) -> Optional[int]:
        """Return spill slot index (multiply by 8 for byte offset from frame base)."""
        return self._spill_slots.get(name)

    def is_known(self, name: str) -> bool:
        return name in self._var_to_reg or name in self._spill_slots

    def all_vars(self) -> List[str]:
        return list(self._var_to_reg) + list(self._spill_slots)

    def used_s_regs(self) -> List[int]:
        return list(self._used_s_regs)

    def spill_count(self) -> int:
        return self._spill_count

    # Temp-reg stack (simple round-robin, good enough for expression trees)
    _temp_idx: int = 0

    def next_temp(self) -> int:
        reg = T_REGS[self._temp_idx % len(T_REGS)]
        self._temp_idx += 1
        return reg

    def reset_temps(self) -> None:
        self._temp_idx = 0


def collect_vars(func) -> List[str]:
    """Collect all assigned variable names in a FuncDef (function args + assignments)."""
    from .ast_nodes import Assign, FuncDef, If, While, Stmt
    seen: List[str] = []
    seen_set: set = set()

    def _add(name: str) -> None:
        if name not in seen_set:
            seen_set.add(name)
            seen.append(name)

    for arg in func.args:
        _add(arg)

    def _scan(stmts) -> None:
        for s in stmts:
            if isinstance(s, Assign):
                _add(s.target)
            elif isinstance(s, If):
                _scan(s.body)
                _scan(s.orelse)
            elif isinstance(s, While):
                _scan(s.body)

    _scan(func.body)
    return seen
