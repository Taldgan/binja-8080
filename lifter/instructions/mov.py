from ..utils import *
__all__ = [
    'MovRegReg',
    'MovRegImm',
    'MovRegMem',
    'MovMemReg',
    'MovToHL',
    'HLToPC',
    'Exchange',
    'HLToSP',
]

# MOV DstReg, SrcReg
class MovRegReg(DstReg, SrcReg):
    _tok_args = [
        ('inst', 'MOV'),
        ('text', ' '),
        ('reg', DstReg),
        ('sep', ','),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# MVI DstReg, D8
class MovRegImm(DstReg, Imm):
    _tok_args = [
        ('inst', 'MVI'),
        ('text', ' '),
        ('reg', DstReg),
        ('sep', ','),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

class MovRegMem(DstReg):
    _tok_args = [
        ('inst', 'MOV'),
        ('text', ' '),
        ('reg', DstReg),
        ('sep', ','),
        ('text', ' '),
        ('s_mem', '['),
        ('reg', 'HL'),
        ('e_mem', ']'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

class MovMemReg(SrcReg):
    _tok_args = [
        ('inst', 'MOV'),
        ('text', ' '),
        ('s_mem', '['),
        ('reg', 'HL'),
        ('e_mem', ']'),
        ('sep', ','),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# XTHL (H = [SP], L = [SP + 1])
class MovToHL():
    _tok_args = [
        ('inst', 'XTHL'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# PCHL (PC.hi = H, PC.low = L)
class HLToPC():
    _tok_args = [
        ('inst', 'PCHL'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# XCHG (H <-> D, L <-> E)
class Exchange():
    _tok_args = [
        ('inst', 'XCHG'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# SPHL (SP = HL)
class HLToSP():
    _tok_args = [
        ('inst', 'SPHL'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
