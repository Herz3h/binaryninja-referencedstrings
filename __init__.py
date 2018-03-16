from binaryninja import *

def start_set_strings_task(bv, ignored):
    task = SetStringsTask(bv)
    task.start()

class SetStringsTask(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, 'Populating String References')
        self.bv = bv

    def run(self):
        self.set_strings(self.bv)

    def set_strings(self, bv):
        for func in bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for inst in bb:
                    if inst.operation == LowLevelILOperation.LLIL_PUSH and inst.src.operation == LowLevelILOperation.LLIL_CONST:
                        # 0x32 bytes of data
                        inst_value = inst.src.value.value
                        strings = bv.get_strings(inst_value, 0x32)

                        # get_strings returns an array of strings at an address, so check first string if located at same requested get_strings address
                        if len(strings) != 0 and strings[0].start == inst_value:
                            first_string = strings[0]
                            comment = str(bv.read(first_string.start, first_string.length))
                            old_comment = func.get_comment_at(inst.address)
                            func.set_comment(inst.address, old_comment + comment)

                            # don't add already added comment
                            if comment not in old_comment:
                                func.set_comment(inst.address, old_comment + comment)

PluginCommand.register_for_address("Set Referenced Strings", "Sets referenced strings as comments whenever a pointer is found and points to a string even if the section is writable", start_set_strings_task)
