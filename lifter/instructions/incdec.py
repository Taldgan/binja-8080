from ..utils import *

__all__ = [
    'IncReg',
    'IncMem',
    'IncReg16',
    'IncMem',
    'DecReg',
    'DecReg16',
]
# Reg (8 bit) += 1
class IncReg(Reg):
    _tok_args = [
        ('inst', 'INR'),
        ('text', ' '),
        ('reg', Reg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width

# INR M
class IncMem(Reg):
    _tok_args = [
        ('inst', 'INR'),
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
    


# Reg (16 bit) += 1
class IncReg16(Reg):
    _tok_args = [
        ('inst', 'INX'),
        ('text', ' '),
        ('reg', Reg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# Reg (8 bit) -= 1
class DecReg(Reg):
    _tok_args = [
        ('inst', 'DCR'),
        ('text', ' '),
        ('reg', Reg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# Reg (16 bit) -= 1
class DecReg16(Reg):
    _tok_args = [
        ('inst', 'DCX'),
        ('text', ' '),
        ('reg', Reg),
    ]

    _width = 1

    def getTokens(self, addr):
        tokens = [makeToken(tok) for tok in self._tok_args]
        return tokens

    def getWidth(self):
        return self._width


# DCR [HL] ([HL] -= 1)
class DecMem(Reg):
    _tok_args = [
        ('inst', 'DCR'),
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
