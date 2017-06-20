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
        log.log_debug('here')
        for func in bv.functions:
            for bb in func.low_level_il.basic_blocks:
                for inst in bb:
                    if inst.operation == LowLevelILOperation.LLIL_PUSH:
                        if inst.src.operation == LowLevelILOperation.LLIL_CONST:
                            strings = bv.get_strings(inst.src.value.value, 0x32)
                            if len(strings) != 0:
                                if strings[0].start == inst.src.value.value:
                                    comment = str(bv.read(strings[0].start, strings[0].length))
                                    old_comment = func.get_comment_at(inst.address)
                                    func.set_comment(inst.address, old_comment + comment)
                                    if comment not in old_comment:
                                        func.set_comment(inst.address, old_comment + comment)

PluginCommand.register_for_address("Set Referenced Strings", "Sets referenced strings as comments whenever a pointer is found and points to a string even if the section is writable", start_set_strings_task)
