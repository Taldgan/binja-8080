from ..utils import *

"""
Interrupts, NOP, and other/'special' instructions
"""
__all__ = [
    'NOP',
    'DAA',
    'DI',
    'EI',
    'HLT',
    'IN',
    'OUT',
]

# NOP (No Operation)
class NOP():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'NOP'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.nop()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1
    
# DAA ???
class DAA():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'NOP'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        
    @staticmethod
    def getWidth():
        return 1


# DI ???
class DI():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'DI'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        
    @staticmethod
    def getWidth():
        return 1


# EI ???
class EI():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'EI'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        
    @staticmethod
    def getWidth():
        return 1


# IN
class IN():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'IN'),
            ('text', ' '),
            ('int', hex(Imm)),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        
    @staticmethod
    def getWidth():
        return 2


# OUT
class OUT():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'OUT'),
            ('text', ' '),
            ('int', hex(Imm)),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        
    @staticmethod
    def getWidth():
        return 2

# HALT
class HLT():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'HLT'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        
    @staticmethod
    def getWidth():
        return 1
