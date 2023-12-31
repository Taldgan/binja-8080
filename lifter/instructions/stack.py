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
class PushReg(SrcReg):
    _tok_args = [        
        ('inst', 'PUSH'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

    
# PUSH PSW
class PushAFlags(SrcReg):
    _tok_args = [        
        ('inst', 'PUSH'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# POP SrcReg
class PopReg(SrcReg):
    _tok_args = [        
        ('inst', 'POP'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

    
# POP PSW
class PopAFlags(SrcReg):
    _tok_args = [        
        ('inst', 'POP'),
        ('text', ' '),
        ('reg', SrcReg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width
    
