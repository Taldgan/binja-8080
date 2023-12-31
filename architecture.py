from binaryninja import Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition
from .lifter import disassemble
import struct

class Intel8080(Architecture):
    name = "8080"
    address_size = 2
    default_int_size = 1
    max_instr_length = 3
    stack_pointer = 'sp'

    regs = {
        'a' : RegisterInfo('a', 1),
        'bc' : RegisterInfo('bc', 2),
            'b' : RegisterInfo('bc', 1, 0),
            'c' : RegisterInfo('bc', 1, 1),
        'de' : RegisterInfo('de', 2),
            'd' : RegisterInfo('de', 1, 0),
            'e' : RegisterInfo('de', 1, 1),
        'hl' : RegisterInfo('hl', 2),
            'h' : RegisterInfo('hl', 1, 0),
            'l' : RegisterInfo('hl', 1, 1),
        'sp' : RegisterInfo('sp', 2),
        'pc' : RegisterInfo('pc', 2),
    }
    flags = [
        'cy', # carry
        'z',  # zero
        'p',  # parity
        's',  # sign
        'ac',  # auxilliary carry
    ]
    flag_roles = {
        'cy' : FlagRole.CarryFlagRole,
        'p' : FlagRole.OddParityFlagRole,
        'ac' : FlagRole.HalfCarryFlagRole,
        'z' : FlagRole.ZeroFlagRole,
        's': FlagRole.NegativeSignFlagRole,
    }
    flag_write_types = [
        '',
        '*',
    ]
    flags_written_by_flag_write_type = {
        '*' : ['cy', 'p', 'ac', 'z', 's'],
    }

    def get_instruction_info(self, data, addr):
        text, inst_len = disassemble.disas(data)
        info = InstructionInfo()
        info.length = inst_len
        return info

    def get_instruction_text(self, data, addr):
        return disassemble.disas(data)

    def get_instruction_low_level_il(self, data, addr, il):
        pass

Intel8080.register()
print("ligma balls")
