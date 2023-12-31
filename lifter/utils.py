from binaryninja import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

# Taken from https://blog.ret2.io/2017/10/17/untangling-exotic-architectures-with-binary-ninja/
def makeToken(tokenType, text, data=None):
    tokenType = {
            'inst':InstructionTextTokenType.InstructionToken,
            'reg':InstructionTextTokenType.RegisterToken,
            'text':InstructionTextTokenType.TextToken,
            'addr':InstructionTextTokenType.PossibleAddressToken,
            's_mem':InstructionTextTokenType.BeginMemoryOperandToken,
            'e_mem':InstructionTextTokenType.EndMemoryOperandToken,
            'int':InstructionTextTokenType.IntegerToken,
            'sep':InstructionTextTokenType.OperandSeparatorToken
    }[tokenType]

    if data is None:
        return InstructionTextToken(tokenType, text)
    return InstructionTextToken(tokenType, text, data)
