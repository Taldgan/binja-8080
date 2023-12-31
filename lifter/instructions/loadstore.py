from ..utils import *

__all__ = [
    'LoadRegImm',
    'LoadAccumulatorMem',
    'LoadAccumulatorRegMem',
    'LoadMemReg',
    'StoreAddrA',
    'StoreMemA',
]

# LXI REG, D16
class LoadRegImm(DstReg, Imm):
    _tok_args = [        
        ('inst', 'LXI'),
        ('text', ' '),
        ('reg', DstReg),
        ('sep', ','),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# LDA (A <- [addr])
class LoadAccumulatorMem(Addr):
    _tok_args = [
        ('inst', 'LDA'),
        ('text', ' '),
        ('reg', 'A'),
        ('sep', ','),
        ('text', ' '),
        ('s_mem', '['),
        ('addr', hex(Addr)),
        ('e_mem', ']'),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# LDAX (A <- [SrcReg])
class LoadAccumulatorRegMem(SrcReg):
    _tok_args = [
        ('inst', 'LDA'),
        ('text', ' '),
        ('reg', 'A'),
        ('sep', ','),
        ('text', ' '),
        ('s_mem', '['),
        ('reg', SrcReg),
        ('e_mem', ']'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
# LHLD (HL = [addr])
class LoadMemReg(Addr):
    _tok_args = [
        ('inst', 'LHLD'),
        ('text', ' '),
        ('s_mem', '['),
        ('addr', Addr),
        ('e_mem', ']'),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# SHLD ([addr] = HL)
class StoreMemReg(Addr):
    _tok_args = [
        ('inst', 'SHLD'),
        ('text', ' '),
        ('s_mem', '['),
        ('addr', Addr),
        ('e_mem', ']'),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# STA addr
class StoreAddrA(Addr):
    _tok_args = [
        ('inst', 'STA'),
        ('text', ' '),
        ('s_mem', '['),
        ('addr', Addr),
        ('e_mem', ']'),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# STAX DstReg ([DstReg] <- A)
class StoreMemA(DstReg):
    _tok_args = [
        ('inst', 'STAX'),
        ('text', ' '),
        ('s_mem', '['),
        ('reg', DstReg),
        ('e_mem', ']'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

