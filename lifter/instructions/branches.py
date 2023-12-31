from ..utils import *

"""
Branches (Jumps, Calls, Ret)
"""

__all__ = [
    'UnconditionalJump',
    'JumpNotZero',
    'JumpZero',
    'JumpCarry',
    'JumpNotCarry',
    'JumpParityOdd',
    'JumpParityEven',
    'JumpPositive',
    'JumpMinus',
    'UnconditionalCall',
    'CallZero',
    'CallNotZero',
    'CallCarry',
    'CallNotCarry',
    'CallParityOdd',
    'CallParityEven',
    'CallPositive',
    'CallMinus',
    'UnconditionalReturn',
    'ReturnZero',
    'ReturnNotZero',
    'ReturnCarry',
    'ReturnNotCarry',
    'ReturnParityOdd',
    'ReturnParityEven',
    'ReturnPositive',
    'ReturnMinus',
    'Reset',
]

# Jumps

# JMP Addr
class UnconditionalJump(Imm):
    _tok_args = [        
        ('inst', 'JMP'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# JNZ Addr
class JumpNotZero(Imm):
    _tok_args = [        
        ('inst', 'JNZ'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# JZ Addr
class JumpZero(Imm):
    _tok_args = [        
        ('inst', 'JZ'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# JC Addr
class JumpCarry(Imm):
    _tok_args = [        
        ('inst', 'JC'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# JNC Addr
class JumpNotCarry(Imm):
    _tok_args = [        
        ('inst', 'JNC'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# JPO Addr
class JumpParityOdd(Imm):
    _tok_args = [        
        ('inst', 'JPO'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# JPE Addr
class JumpParityEven(Imm):
    _tok_args = [        
        ('inst', 'JPE'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# JP Addr
class JumpPositive(Imm):
    _tok_args = [        
        ('inst', 'JP'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# JM Addr
class JumpMinus(Imm)
    _tok_args = [        
        ('inst', 'JM,'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# Calls

# CALL Addr
class UnconditionalCall(Imm):
    _tok_args = [        
        ('inst', 'CALL'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# CZ Addr
class CallZero(Imm):
    _tok_args = [        
        ('inst', 'CZ'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# CNZ Addr
class CallNotZero(Imm):
    _tok_args = [        
        ('inst', 'CNZ'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# CC Addr
class CallCarry(Imm):
    _tok_args = [        
        ('inst', 'CC'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# CNC Addr
class CallNotCarry(Imm):
    _tok_args = [        
        ('inst', 'CNC'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# CPO Addr
class CallParityOdd(Imm):
    _tok_args = [        
        ('inst', 'CPO'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# CPE Addr
class CallParityEven(Imm):
    _tok_args = [        
        ('inst', 'CPE'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# CP Addr
class CallPositive(Imm):
    _tok_args = [        
        ('inst', 'CP'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# CM Addr
class CallMinus(Imm):
    _tok_args = [        
        ('inst', 'CM'),
        ('text', ' '),
        ('addr', hex(Imm)),
    ]

    _width = 3

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# Returns

# RET
class UnconditionalReturn():    
    _tok_args = [        
        ('inst', 'RET'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
# RZ
class ReturnZero():    
    _tok_args = [        
        ('inst', 'RZ'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RNZ
class ReturnNotZero():    
    _tok_args = [        
        ('inst', 'RNZ'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RC
class ReturnCarry():    
    _tok_args = [        
        ('inst', 'RC'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RNC
class ReturnNotCarry():    
    _tok_args = [        
        ('inst', 'RNC'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RPO
class ReturnParityOdd():    
    _tok_args = [        
        ('inst', 'RPO'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RPE
class ReturnParityEven():    
    _tok_args = [        
        ('inst', 'RPE'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# RP
class ReturnPositive():    
    _tok_args = [        
        ('inst', 'RP'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# RM
class ReturnMinus():    
    _tok_args = [        
        ('inst', 'RM'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# Resets?

class Reset(Imm):
    _tok_args = [        
        ('inst', 'RST'),
        ('text', ' '),
        ('int', Imm),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
