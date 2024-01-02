from binaryninja import Architecture, RegisterInfo, IntrinsicInfo, InstructionInfo, InstructionTextToken, InstructionTextTokenType
from binaryninja.enums import Endianness, FlagRole, LowLevelILFlagCondition
from .lifter import analyze
import struct

class Intel8080(Architecture):
    name = "8080"
    address_size = 2
    default_int_size = 1
    max_instr_length = 3
    stack_pointer = 'SP'

    regs = {
        'A' : RegisterInfo('A', 1),
        'BC' : RegisterInfo('BC', 2),
            'B' : RegisterInfo('BC', 1, 0),
            'C' : RegisterInfo('BC', 1, 1),
        'DE' : RegisterInfo('DE', 2),
            'D' : RegisterInfo('DE', 1, 0),
            'E' : RegisterInfo('DE', 1, 1),
        'HL' : RegisterInfo('HL', 2),
            'H' : RegisterInfo('HL', 1, 0),
            'L' : RegisterInfo('HL', 1, 1),
        'SP' : RegisterInfo('SP', 2),
        'PC' : RegisterInfo('PC', 2),
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
        text, inst_len = analyze.disas(data, addr)
        info = InstructionInfo()
        info.length = inst_len
        info = analyze.branch_info(data, addr, info)
        return info

    def get_instruction_text(self, data, addr):
        text_tokens, inst_len = analyze.disas(data, addr)
        # print(text_tokens)
        return text_tokens, inst_len

    def get_instruction_low_level_il(self, data, addr, il):
        pass

Intel8080.register()
