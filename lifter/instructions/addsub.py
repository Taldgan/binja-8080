from ..utils import *

"""
Add/Sub/Compare Operations
"""

__all__= [
    'AddReg',
    'AddImm',
    'AddMem',
    'AddDataWithCarry',
    'AddRegWithCarry',
    'AddMemWithCarry',
    'AddHLReg',
    'SubReg',
    'SubRegWithCarry',
    'SubMem',
    'SubMemWithCarry',
    'SubImm',
    'CompareReg',
    'CompareMem',
    'CompareImm',
]   

# A = A + Reg, sets Z, S, P, CY, AC
class AddReg(SrcReg):
    _tok_args = [        
        ('inst', 'ADD'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# ADI (A = A + D8)
class AddImm(Imm):
    _tok_args = [        
        ('inst', 'ADI'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# A = A + [HL], sets Z, S, P, CY, AC
class AddMem(SrcReg):
    _tok_args = [        
        ('inst', 'ADD'),
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

# ACI (A = A + D8 + CY)
class AddDataWithCarry(Imm):
    _tok_args = [        
        ('inst', 'ACI'),
        ('text', ' '),
        ('int', Imm),
    ] 
    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# ADC SrcReg (A = A + Reg + CY)
class AddRegWithCarry(SrcReg):
    _tok_args = [        
        ('inst', 'ADC'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# ADC M (A = A + [HL] + CY)
class AddMemWithCarry():
    _tok_args = [        
        ('inst', 'ADC'),
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

# DAD SrcReg (HL = HL + SrcReg)
class AddHLReg(SrcReg):
    _tok_args = [        
        ('inst', 'DAD'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width



# SUB SrcReg (A = A - SrcReg)
class SubReg(SrcReg):
    _tok_args = [        
        ('inst', 'SUB'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# SBB SrcReg (A = A - SrcReg - CY)
class SubRegWithCarry(SrcReg):
    _tok_args = [        
        ('inst', 'SBB'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# SUB [HL]  (A = A - [HL], sets Z, S, P, CY, AC)
class SubMem(SrcReg):
    _tok_args = [        
        ('inst', 'SUB'),
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

# SBB [HL] (A = A - [HL] - CY)
class SubMemWithCarry():
    _tok_args = [        
        ('inst', 'SBB'),
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

# SUI (A = A - D8)
class SubImm(Imm):
    _tok_args = [        
        ('inst', 'SUI'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# SBI (A = A - D8 - CY)
class SubImmWithCarry(Imm):
    _tok_args = [        
        ('inst', 'SBI'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# Comparisons...

# CMP SrcReg (A - B, set Z, S, P, CY, AC)
class CompareReg(SrcReg):
    _tok_args = [        
        ('inst', 'CMP'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# CMP [HL] (A - [HL], set Z, S, P, CY, AC)
class CompareMem():
    _tok_args = [        
        ('inst', 'CMP'),
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


# CPI (A - D8)
class CompareImm(Imm):
    _tok_args = [        
        ('inst', 'CPI'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

