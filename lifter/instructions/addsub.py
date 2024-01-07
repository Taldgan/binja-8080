from ..utils import *

"""
Add/Sub/Compare Operations
"""

__all__= [
    'AddReg',
    'AddImm',
    'AddMem',
    'AddImmWithCarry',
    'AddRegWithCarry',
    'AddMemWithCarry',
    'AddHLReg',
    'SubReg',
    'SubRegWithCarry',
    'SubMem',
    'SubMemWithCarry',
    'SubImm',
    'SubImmWithCarry',
    'CompareReg',
    'CompareMem',
    'CompareImm',
]   

# A = A + Reg, sets Z, S, P, CY, AC
class AddReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'ADD'),
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

# ADI (A = A + D8)
class AddImm():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'ADI'),
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
    
# A = A + [HL], sets Z, S, P, CY, AC
class AddMem():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'ADD'),
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

# ACI (A = A + D8 + CY)
class AddImmWithCarry():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'ACI'),
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

# ADC SrcReg (A = A + Reg + CY)
class AddRegWithCarry():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'ADC'),
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

# ADC M (A = A + [HL] + CY)
class AddMemWithCarry():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'ADC'),
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

# DAD SrcReg (HL = HL + SrcReg)
class AddHLReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'DAD'),
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



# SUB SrcReg (A = A - SrcReg)
class SubReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'SUB'),
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

# SBB SrcReg (A = A - SrcReg - CY)
class SubRegWithCarry():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'SBB'),
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

# SUB [HL]  (A = A - [HL], sets Z, S, P, CY, AC)
class SubMem():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'SUB'),
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

# SBB [HL] (A = A - [HL] - CY)
class SubMemWithCarry():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'SBB'),
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

# SUI (A = A - D8)
class SubImm():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'SUI'),
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

# SBI (A = A - D8 - CY)
class SubImmWithCarry():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'SBI'),
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

# Comparisons...

# CMP SrcReg (A - B, set Z, S, P, CY, AC)
class CompareReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'CMP'),
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

# CMP [HL] (A - [HL], set Z, S, P, CY, AC)
class CompareMem():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'CMP'),
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


# CPI (A - D8)
class CompareImm():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CPI'),
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

