from binaryninja.lowlevelil import LLIL_TEMP
from ..utils import *
__all__ = [
    'MovRegReg',
    'MovRegImm',
    'MovRegMem',
    'MovMemReg',
    'MovMemImm',
    'MovToHL',
    'HLToPC',
    'Exchange',
    'HLToSP',
]

# MOV DstReg, SrcReg
class MovRegReg():
    def __init__(self, DstReg, SrcReg):
        self._tok_args = [
            ('inst', 'MOV'),
            ('text', ' '),
            ('reg', DstReg),
            ('sep', ','),
            ('text', ' '),
            ('reg', SrcReg),
        ]
        self._dst_reg = DstReg
        self._src_reg = SrcReg

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.set_reg(1, self._dst_reg, il.reg(1, self._src_reg))
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

# MVI DstReg, D8
class MovRegImm():
    def __init__(self, DstReg, Imm):
        self._tok_args = [
            ('inst', 'MVI'),
            ('text', ' '),
            ('reg', DstReg),
            ('sep', ','),
            ('text', ' '),
            ('int', hex(Imm)),
        ]
        self._dst_reg = DstReg
        self._imm = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.set_reg(1, self._dst_reg, il.const(1, self._imm))
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 2

# MVI [HL], D8
class MovMemImm():
    def __init__(self, Imm):
        self._tok_args = [
            ('inst', 'MVI'),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', 'HL'),
            ('e_mem', ']'),
            ('sep', ','),
            ('text', ' '),
            ('int', hex(Imm)),
        ]
        self._imm = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.store(1, il.reg(2, 'HL'), il.const(1, self._imm))
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 2

class MovRegMem():
    def __init__(self, DstReg):
        self._tok_args = [
            ('inst', 'MOV'),
            ('text', ' '),
            ('reg', DstReg),
            ('sep', ','),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', 'HL'),
            ('e_mem', ']'),
        ]
        self._dst_reg = DstReg

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        subexpr = il.load(1, il.reg(2, 'HL'))
        expr = il.set_reg(1, self._dst_reg, subexpr)
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

class MovMemReg():
    def __init__(self, SrcReg):
        self._tok_args = [
            ('inst', 'MOV'),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', 'HL'),
            ('e_mem', ']'),
            ('sep', ','),
            ('text', ' '),
            ('reg', SrcReg),
        ]
        self._src_reg = SrcReg

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.store(1, il.reg(2, 'HL'), il.reg(1, self._src_reg))
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

# XTHL (H = [SP], L = [SP + 1])
class MovToHL():
    def __init__(self):
        self._tok_args = [
            ('inst', 'XTHL'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        # Load 2 bytes from reg sp, set hl to those 2 bytes
        expr = il.set_reg(2, 'HL', il.load(2, il.reg(2, 'SP')))
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

# PCHL (PC.hi = H, PC.low = L)
class HLToPC():
    def __init__(self):
        self._tok_args = [
            ('inst', 'PCHL'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.set_reg(2, 'PC', il.reg(2, 'HL'))
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

# XCHG (H <-> D, L <-> E)
class Exchange():
    def __init__(self):
        self._tok_args = [
            ('inst', 'XCHG'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        tmp_reg = LLIL_TEMP(il.temp_reg_count)
        # Set temp to 'DE'
        il.append(il.set_reg(2, tmp_reg, il.reg(2, 'DE')))
        # Set 'DE' to 'HL'
        il.append(il.set_reg(2, 'DE', il.reg(2, 'HL')))
        # Set 'HL' to 'tmp'
        il.append(il.set_reg(2, 'HL', tmp_reg))
        
    @staticmethod
    def getWidth():
        return 1

# SPHL (SP = HL)
class HLToSP():
    def __init__(self):
        self._tok_args = [
            ('inst', 'SPHL'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.set_reg(2, 'SP', il.reg(2, 'HL'))
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1
