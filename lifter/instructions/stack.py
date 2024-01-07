from binaryninja.lowlevelil import LLIL_TEMP
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
        self._flags = [
            ('z', 0),  # zero
            ('s', 1),  # sign
            ('p', 2),  # parity
            ('cy', 3), # carry
            ('ac', 4), # auxilliary carry
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        # get A reg
        a_reg = il.reg(1, 'A')

        # get flags (AC CY P S Z) as expression
        flags = None
        for flag, ind in self._flags:
            flag_bit = il.flag_bit(1, flag, ind)
            if flags is None:
                flags = flag_bit
            else:
                flags = il.or_expr(1, flag_bit, flags)
        # PSW = A | Flags
        psw = il.or_expr(2, il.shift_left(2, a_reg, il.const(1, 8)), flags)
        expr = il.push(2, psw)
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
        self._flags = [
            ('z', 0),  # zero
            ('s', 1),  # sign
            ('p', 2),  # parity
            ('cy', 3), # carry
            ('ac', 4), # auxilliary carry
        ]

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        # Create psw temp register
        psw = LLIL_TEMP(il.temp_reg_count)

        # Set psw to the value popped from stack
        subexpr = il.set_reg(2, psw, il.pop(2))
        il.append(subexpr)

        # Extract 'A'
        a_val = il.logical_shift_right(1, psw, il.const(1, 8))
        expr = il.set_reg(1, 'A', a_val)
        il.append(expr)

        # Extract and set flags
        flags = il.and_expr(1, psw, il.const(1, 0xff))

        for flag, ind in self._flags:
            # Get value of bit out of flags temp register
            bit_value = il.test_bit(1, il.reg(1, flags), il.const(1, ind))
            # Finally, set the respective flag to the extracted value
            il.append(il.set_flag(flag, bit_value))

        
    @staticmethod
    def getWidth():
        return 1
    
