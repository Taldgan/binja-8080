from ..utils import *

"""
Interrupts, NOP, and other/'special' instructions
"""
__all__ = [
    'NOP',
    'DAA',
    'DI',
    'EI',
]
# NOP (No Operation)
class NOP():
    _tok_args = [        
        ('inst', 'NOP'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
# DAA ???
class DAA():
    _tok_args = [        
        ('inst', 'NOP'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# DI ???
class DI():
    _tok_args = [        
        ('inst', 'DI'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# EI ???
class EI():
    _tok_args = [        
        ('inst', 'EI'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# IN
class IN(Imm):
    _tok_args = [        
        ('inst', 'IN'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# OUT
class OUT(Imm):
    _tok_args = [        
        ('inst', 'OUT'),
        ('text', ' '),
        ('int', hex(Imm)),
    ]

    _width = 2

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# HALT
class HLT():
    _tok_args = [        
        ('inst', 'HLT'),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
