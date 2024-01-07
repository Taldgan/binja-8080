from ..utils import *

"""
Bitwise/ALU Operations (And/Or/Xor/Not)    
"""
__all__ = [
    'AndAccumulatorReg',
    'AndAccumulatorImm',
    'AndAccumulatorMem',
    'XorAccumulatorReg',
    'XorAccumulatorImm',
    'XorAccumulatorMem',
    'OrAccumulatorReg',
    'OrAccumulatorImm',
    'OrAccumulatorMem',
    'RotateAccumulatorLeftWithCarry',
    'RotateAccumulatorRightWithCarry',
    'RotateAccumulatorLeft',
    'RotateAccumulatorRight',
    'NotAccumulator',
    'SetCarry',
    'NotCarry',
]

# ANA SrcReg (A = A & SrcReg)
class AndAccumulatorReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'ANA'),
            ('text', ' '),
            ('reg', SrcReg),
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

# ANI (A = A & D8)
class AndAccumulatorImm():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'ANI'),
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
        return 2

# ANA M (A = A & [HL])
class AndAccumulatorMem():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'ANA'),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', 'HL'),
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


# XRA SrcReg (A = A ^ SrcReg)
class XorAccumulatorReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'XRA'),
            ('text', ' '),
            ('reg', SrcReg),
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

# XRI (A = A ^ D8)
class XorAccumulatorImm():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'XRI'),
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
        return 2

# XRA M (A = A ^ [HL])
class XorAccumulatorMem():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'XRA'),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', 'HL'),
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


# ORA SrcReg (A = A | SrcReg)
class OrAccumulatorReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'ORA'),
            ('text', ' '),
            ('reg', SrcReg),
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

# ORI (A = A | D8)
class OrAccumulatorImm():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'ORI'),
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
        return 2

# ORA M (A = A | [HL])
class OrAccumulatorMem():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'ORA'),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', 'HL'),
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

# RLC (A = A << 1), rotate A left
class RotateAccumulatorLeftWithCarry():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RLC'),
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

# RRC (A = A >> 1), rotate A right
class RotateAccumulatorRightWithCarry():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RRC'),
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

# RAL (A = A << 1)
class RotateAccumulatorLeft():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RAL'),
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

# RAR (A = A >> 1)
class RotateAccumulatorRight():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RAR'),
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

# CMA (A = !A)
class NotAccumulator():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'CMA'),
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

# STC (CY = 1)
class SetCarry():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'STC'),
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

# CMC (CY = !CY)
class NotCarry():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'CMC'),
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
