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
    'NotCary',
]

# ANA SrcReg (A = A & SrcReg)
class AndAccumulatorReg(SrcReg):
    _tok_args = [        
        ('inst', 'ANA'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# ANI (A = A & D8)
class AndAccumulatorImm(Imm):
    _tok_args = [        
        ('inst', 'ANI'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# ANA M (A = A & [HL])
class AndAccumulatorMem():
    _tok_args = [        
        ('inst', 'ANA'),
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


# XRA SrcReg (A = A ^ SrcReg)
class XorAccumulatorReg(SrcReg):
    _tok_args = [        
        ('inst', 'XRA'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# XRI (A = A ^ D8)
class XorAccumulatorImm(Imm):
    _tok_args = [        
        ('inst', 'XRI'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# XRA M (A = A ^ [HL])
class XorAccumulatorMem():
    _tok_args = [        
        ('inst', 'XRA'),
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


# ORA SrcReg (A = A | SrcReg)
class OrAccumulatorReg(SrcReg):
    _tok_args = [        
        ('inst', 'ORA'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# ORI (A = A | D8)
class OrAccumulatorImm(Imm):
    _tok_args = [        
        ('inst', 'ORI'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# ORA M (A = A | [HL])
class OrAccumulatorMem():
    _tok_args = [        
        ('inst', 'ORA'),
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

# RLC (A = A << 1), rotate A left
class RotateAccumulatorLeftWithCarry():
    _tok_args = [        
        ('inst', 'RLC'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RRC (A = A >> 1), rotate A right
class RotateAccumulatorRightWithCarry():
    _tok_args = [        
        ('inst', 'RRC'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RAL (A = A << 1)
class RotateAccumulatorLeft():
    _tok_args = [        
        ('inst', 'RAL'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RAR (A = A >> 1)
class RotateAccumulatorRight():
    _tok_args = [        
        ('inst', 'RAR'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# CMA (A = !A)
class NotAccumulator():
    _tok_args = [        
        ('inst', 'CMA'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# STC (CY = 1)
class SetCarry():
    _tok_args = [        
        ('inst', 'STC'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# CMC (CY = !CY)
class NotCary():
    _tok_args = [        
        ('inst', 'CMC'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
