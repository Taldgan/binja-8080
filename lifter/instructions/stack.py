from ..utils import *
""" 
Stack Operations (Push/Pop)    
"""

__all__ = [
    'PushReg',
    'PushAFlags',
    'PopReg',
    'PopAFlags',
]

# PUSH SrcReg
class PushReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'PUSH'),
            ('text', ' '),
            ('reg', SrcReg),
        ]
        self._reg = SrcReg

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        subexpr = il.reg(2, self._reg)
        expr = il.push(2, subexpr)
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

    
# PUSH PSW
class PushAFlags():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'PUSH PSW'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        subexpr = il.reg(2, self._reg)
        expr = il.push(2, subexpr)
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1


# POP SrcReg
class PopReg():
    def __init__(self, SrcReg):
        self._tok_args = [        
            ('inst', 'POP'),
            ('text', ' '),
            ('reg', SrcReg),
        ]
        self._reg = SrcReg

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        subexpr = il.pop(2)
        reg = self._reg
        expr = il.set_reg(2, reg, subexpr)
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

    
# POP PSW
class PopAFlags():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'POP PSW'),
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
    
