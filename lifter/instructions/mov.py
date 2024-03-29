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

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

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

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

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

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

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

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

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

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

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

    @staticmethod
    def getWidth():
        return 1
