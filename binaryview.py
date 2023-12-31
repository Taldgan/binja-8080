from binaryninja import Architecture, Platform, BinaryView
from binaryninja.enums import SegmentFlag, SectionSemantics

__all__ = ['CPMComBinaryView']

class CPMComBinaryView(BinaryView):
    name = "COM"
    long_name = "CP/M .COM Executable"
    @classmethod
    def is_valid_for_data(cls, data):
        if not data.file.filename.lower().endswith('.com'):
            return False
        return True

    def __init__(self, data):
        BinaryView.__init__(self, data.file, data)

        self.arch = Architecture['8080']
        self.platform = Platform['8080']

    def init(self):
        data = self.parent_view

        seg_rw_  = (SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentWritable)
        seg_rwx  = (SegmentFlag.SegmentExecutable |
                    seg_rw_)
        seg_code = SegmentFlag.SegmentContainsCode
        seg_data = SegmentFlag.SegmentContainsData
        self.add_auto_segment(0x0100, data.length,
                              data.start, data.length,
                              seg_rwx|seg_code|seg_data)
        sec_text = SectionSemantics.ReadOnlyCodeSectionSemantics
        sec_data = SectionSemantics.ReadWriteDataSectionSemantics
        self.add_auto_section('.text', 0x0100, len(data),
                              sec_text)
        self.add_auto_section('.data', 0x0100, len(data),
                              sec_data)

        self.navigate('Linear:COM', self.entry_point)

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x0100

CPMComBinaryView.register()
