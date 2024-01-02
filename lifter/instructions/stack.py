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

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

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

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

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

    @staticmethod
    def getWidth():
        return 1
    
