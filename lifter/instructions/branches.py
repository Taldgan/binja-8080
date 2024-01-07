from binaryninja import InstructionInfo, BranchType
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
class UnconditionalJump():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JMP'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.UnconditionalBranch, self._branch)
        return info

# JNZ Addr
class JumpNotZero():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JNZ'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.TrueBranch, self._branch)
        info.add_branch(BranchType.FalseBranch, addr + self.getWidth())
        return info

# JZ Addr
class JumpZero():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JZ'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.TrueBranch, self._branch)
        info.add_branch(BranchType.FalseBranch, addr + self.getWidth())
        return info


# JC Addr
class JumpCarry():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JC'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.TrueBranch, self._branch)
        info.add_branch(BranchType.FalseBranch, addr + self.getWidth())
        return info


# JNC Addr
class JumpNotCarry():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JNC'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.TrueBranch, self._branch)
        info.add_branch(BranchType.FalseBranch, addr + self.getWidth())
        return info

# JPO Addr
class JumpParityOdd():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JPO'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.TrueBranch, self._branch)
        info.add_branch(BranchType.FalseBranch, addr + self.getWidth())
        return info


# JPE Addr
class JumpParityEven():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JPE'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.TrueBranch, self._branch)
        info.add_branch(BranchType.FalseBranch, addr + self.getWidth())
        return info

# JP Addr
class JumpPositive():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JP'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.TrueBranch, self._branch)
        info.add_branch(BranchType.FalseBranch, addr + self.getWidth())
        return info

# JM Addr
class JumpMinus():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'JM'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.TrueBranch, self._branch)
        info.add_branch(BranchType.FalseBranch, addr + self.getWidth())
        return info

# Calls

# CALL Addr
class UnconditionalCall():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CALL'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info

# CZ Addr
class CallZero():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CZ'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info
    
# CNZ Addr
class CallNotZero():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CNZ'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info
    
# CC Addr
class CallCarry():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CC'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info
    
# CNC Addr
class CallNotCarry():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CNC'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info
    
# CPO Addr
class CallParityOdd():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CPO'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info
    
# CPE Addr
class CallParityEven():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CPE'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info
    
# CP Addr
class CallPositive():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CP'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info
    
# CM Addr
class CallMinus():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', 'CM'),
            ('text', ' '),
            ('addr', hex(Imm)),
        ]
        self._branch = Imm

    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 3

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.CallDestination, self._branch)
        return info

# Returns

# RET
class UnconditionalReturn():    
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RET'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info
# RZ
class ReturnZero():    
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RZ'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info

# RNZ
class ReturnNotZero():    
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RNZ'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info

# RC
class ReturnCarry():    
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RC'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info

# RNC
class ReturnNotCarry():    
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RNC'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info

# RPO
class ReturnParityOdd():    
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RPO'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info

# RPE
class ReturnParityEven():    
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RPE'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info


# RP
class ReturnPositive():
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RP'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info

# RM
class ReturnMinus():    
    def __init__(self):
        self._tok_args = [        
            ('inst', 'RM'),
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

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info


# Resets?

class Reset():
    def __init__(self, Imm):
        self._tok_args = [        
            ('inst', f'RST {Imm}'),
        ]
        self._branch = {
            '0':0,
            '1':8,
            '2':10,
            '3':18,
            '4':20,
            '5':28,
            '6':30,
            '7':38,
        }[Imm]


    def getTokens(self, addr):
        tokens = [makeToken(*tok) for tok in self._tok_args]
        return tokens

    def lift(self, addr, il):
        expr = il.unimplemented()
        il.append(expr)
        
    @staticmethod
    def getWidth():
        return 1

    def getBranch(self, info: InstructionInfo, addr):
        info.add_branch(BranchType.FunctionReturn)
        return info
    
