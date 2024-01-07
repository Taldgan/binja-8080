from ..utils import *

__all__ = [
    'LoadRegImm',
    'LoadAccumulatorMem',
    'LoadAccumulatorRegMem',
    'LoadMemReg',
    'StoreAddrA',
    'StoreMemA',
    'StoreMemReg',
]

# LXI REG, D16
class LoadRegImm():
    def __init__(self, DstReg, Imm):
        self._tok_args = [        
            ('inst', 'LXI'),
            ('text', ' '),
            ('reg', DstReg),
            ('sep', ','),
            ('text', ' '),
            ('int', hex(Imm)),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

# LDA (A <- [addr])
class LoadAccumulatorMem():
    def __init__(self, Addr):
        self._tok_args = [
            ('inst', 'LDA'),
            ('text', ' '),
            ('reg', 'A'),
            ('sep', ','),
            ('text', ' '),
            ('s_mem', '['),
            ('addr', hex(Addr)),
            ('e_mem', ']'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

# LDAX (A <- [SrcReg])
class LoadAccumulatorRegMem():
    def __init__(self, SrcReg):
        self._tok_args = [
            ('inst', 'LDA'),
            ('text', ' '),
            ('reg', 'A'),
            ('sep', ','),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', SrcReg),
            ('e_mem', ']'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

# LHLD (HL = [addr])
class LoadMemReg():
    def __init__(self, Addr):
        self._tok_args = [
            ('inst', 'LHLD'),
            ('text', ' '),
            ('s_mem', '['),
            ('addr', hex(Addr)),
            ('e_mem', ']'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

# SHLD ([addr] = HL)
class StoreMemReg():
    def __init__(self, Addr):
        self._tok_args = [
            ('inst', 'SHLD'),
            ('text', ' '),
            ('s_mem', '['),
            ('addr', hex(Addr)),
            ('e_mem', ']'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

# STA addr
class StoreAddrA():
    def __init__(self, Addr):
        self._tok_args = [
            ('inst', 'STA'),
            ('text', ' '),
            ('s_mem', '['),
            ('addr', hex(Addr)),
            ('e_mem', ']'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

# STAX DstReg ([DstReg] <- A)
class StoreMemA():
    def __init__(self, DstReg):
        self._tok_args = [
            ('inst', 'STAX'),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', DstReg),
            ('e_mem', ']'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

