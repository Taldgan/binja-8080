from ..utils import *

__all__ = [
    'IncReg',
    'IncMem',
    'IncReg16',
    'IncMem',
    'DecReg',
    'DecReg16',
    'DecMem',
]
# Reg (8 bit) += 1
class IncReg():
    def __init__(self, Reg):
        self._tok_args = [
            ('inst', 'INR'),
            ('text', ' '),
            ('reg', Reg),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    @staticmethod
    def getWidth():
        return 1

# INR M
class IncMem():
    def __init__(self):
        self._tok_args = [
            ('inst', 'INR'),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', 'HL'),
            ('e_mem', ']'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    @staticmethod
    def getWidth():
        return 1
    


# Reg (16 bit) += 1
class IncReg16():
    def __init__(self, Reg):
        self._tok_args = [
            ('inst', 'INX'),
            ('text', ' '),
            ('reg', Reg),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    @staticmethod
    def getWidth():
        return 1


# Reg (8 bit) -= 1
class DecReg():
    def __init__(self, Reg):
        self._tok_args = [
            ('inst', 'DCR'),
            ('text', ' '),
            ('reg', Reg),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    @staticmethod
    def getWidth():
        return 1


# Reg (16 bit) -= 1
class DecReg16():
    def __init__(self, Reg):
        self._tok_args = [
            ('inst', 'DCX'),
            ('text', ' '),
            ('reg', Reg),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    @staticmethod
    def getWidth():
        return 1


# DCR [HL] ([HL] -= 1)
class DecMem():
    def __init__(self):
        self._tok_args = [
            ('inst', 'DCR'),
            ('text', ' '),
            ('s_mem', '['),
            ('reg', 'HL'),
            ('e_mem', ']'),
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    @staticmethod
    def getWidth():
        return 1
