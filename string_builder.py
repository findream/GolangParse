'''
针对string类型
采用对rtype_string这个结构进行交叉引用
在text段遍历所有的交叉引用，
'''
#coding = utf-8
import idc
import idautils
import idaapi
idaapi.require("common")
import sys


'''
mov     ebx, offset aWire ; "wire" # Get string
mov     [esp], ebx
mov     dword ptr [esp+4], 4 # String length

mov     ebx, offset unk_8608FD5 # Get string
mov     [esp+8], ebx
mov     dword ptr [esp+0Ch], 0Eh # String length

mov     ebx, offset unk_86006E6 # Get string
mov     [esp+10h], ebx
mov     dword ptr [esp+14h], 5 # String length

mov     ebx, 861143Ch
mov     dword ptr [esp+0F0h+var_E8+4], ebx
mov     [esp+0F0h+var_E0], 19h

# Found in newer versions of golang binaries

lea     rax, unk_8FC736
mov     [rsp+38h+var_18], rax
mov     [rsp+38h+var_10], 1Dh

lea     rdx, unk_8F6E82
mov     [rsp+40h+var_38], rdx
mov     [rsp+40h+var_30], 13h

lea     eax, unk_82410F0
mov     [esp+94h+var_8C], eax
mov     [esp+94h+var_88], 2
'''

class StringParse():
    VALID_REGS = ['eax','ecx','ebx', 'ebp', 'rax', 'rcx', 'r10', 'rdx']
    VALID_DEST = ['esp', 'eax', 'ecx', 'edx', 'rsp']
    def __init__(self,stringtype_addr):
        self.stringtype_addr = stringtype_addr

    def is_const_string(self,addr):
        # Check for first parts instruction and what it is loading -- also ignore function pointers we may have renamed
        if (idc.print_insn_mnem(addr) != 'mov' and idc.print_insn_mnem(addr) != 'lea') \
            and (idc.GetOpType(addr, 1) != 2 or idc.GetOpType(addr, 1) != 5) \
            or idc.print_operand(addr, 1)[-4:] == '_ptr':
            return False

        # Validate that the string offset actually exists inside the binary
        if idc.get_segm_name(idc.GetOperandValue(addr, 1)) is None:
            return False

        # Could be unk_, asc_, 'offset ', XXXXh, ignored ones are loc_ or inside []
        if idc.print_operand(addr, 0) in StringParse.VALID_REGS \
            and not ('[' in idc.print_operand(addr, 1) or 'loc_' in idc.print_operand(addr, 1)) \
            and (('offset ' in idc.print_operand(addr, 1) or 'h' in idc.print_operand(addr, 1)) \
            or ('unk' == idc.print_operand(addr, 1)[:3])):
            from_reg = idc.print_operand(addr, 0)
            # Check for second part
            addr_2 = idc.FindCode(addr, idaapi.SEARCH_DOWN)
            try:
                dest_reg = idc.print_operand(addr_2, 0)[idc.print_operand(addr_2, 0).index('[') + 1:idc.print_operand(addr_2, 0).index('[') + 4]
            except ValueError:
                return False

            if idc.print_insn_mnem(addr_2) == 'mov' and dest_reg in StringParse.VALID_DEST \
                and ('[%s' % dest_reg) in idc.print_operand(addr_2, 0) \
                and idc.print_operand(addr_2, 1) == from_reg:
                # Check for last part, could be improved
                addr_3 = idc.FindCode(addr_2, idaapi.SEARCH_DOWN)
                # GetOpType 1 is a register, potentially we can just check that GetOpType returned 5?
                if idc.print_insn_mnem(addr_3) == 'mov' \
                and (('[%s+' % dest_reg) in idc.print_operand(addr_3, 0) or idc.print_operand(addr_3, 0) in StringParse.VALID_DEST) \
                and 'offset ' not in idc.print_operand(addr_3, 1) and 'dword ptr ds' not in idc.print_operand(addr_3, 1) \
                and idc.GetOpType(addr_3, 1) != 1 and idc.GetOpType(addr_3, 1) != 2 and idc.GetOpType(addr_3, 1) != 4:
                    try:
                        dumb_int_test = idc.GetOperandValue(addr_3, 1)
                        if dumb_int_test > 0 and dumb_int_test < sys.maxsize:
                            return True
                    except ValueError:
                        return False

        return False
    

    def parse_conststring(self):
        strings_added = 0
        retry = []

        # get text segment
        text_seg = common.get_text_seg()
        if not text_seg :
            common._error("text segment in None")
            return 0

        for addr in idautils.Functions(text_seg.startEA, text_seg.endEA):
            name = idc.GetFunctionName(addr)
            func_t = idaapi.get_func(addr)
            addr = func_t.start_ea
            end_addr = func_t.end_ea
            if(end_addr < addr):
                common._error('Unable to find good end for the function %s' % name)
                continue
            common._info("\t\t\t  search string in func:%s\t\t\t  " % name )
            while addr <= end_addr:
                if self.is_const_string(addr):
                    if 'rodata' not in idc.get_segm_name(addr) and 'text' not in idc.get_segm_name(addr):
                        common._debug('Should a string be in the %s section?' % idc.get_segm_name(addr))
                    string_addr = idc.GetOperandValue(addr, 1)
                    if string_addr == 0x0048D207:
                        print("here")
                    addr_3 = idc.FindCode(idc.FindCode(addr, idaapi.SEARCH_DOWN), idaapi.SEARCH_DOWN)
                    string_len = idc.GetOperandValue(addr_3, 1)
                    if string_len > 1:
                        if self.create_string(string_addr, string_len):
                            if self.create_offset(addr):
                                strings_added += 1
                        else:
                            # There appears to be something odd that goes on with IDA making some strings, always works
                            # the second time, so lets just force a retry...
                            retry.append((addr, string_addr, string_len))

                    # Skip the extra mov lines since we know it won't be a load on any of them
                    addr = idc.FindCode(addr_3, idaapi.SEARCH_DOWN)
                else:
                    addr = idc.FindCode(addr, idaapi.SEARCH_DOWN)

        for instr_addr, string_addr, string_len in retry:
            if self.create_string(string_addr, string_len):
                if self.create_offset(instr_addr):
                    strings_added += 1
            else:
                common._error('Unable to make a string @ 0x%x with length of %d for usage in function @ 0x%x' % (string_addr, string_len, instr_addr))

        return strings_added

    def is_ptr_string(self,addr):
        if idc.print_insn_mnem(addr) =="lea" and idc.GetOpnd(addr, 0) in StringParse.VALID_REGS and idc.GetOpnd(addr, 0) == idc.GetOpnd(idc.FindCode(addr, idaapi.SEARCH_DOWN), 1) and 'off_' in idc.GetOpnd(idc.FindCode(idc.FindCode(addr,idaapi.SEARCH_DOWN),idaapi.SEARCH_DOWN), 1):
            return idc.FindCode(idc.FindCode(addr,idaapi.SEARCH_DOWN),idaapi.SEARCH_DOWN)
        else:
            return

    def parse_ptrstring(self):
        strings_added = 0
        addr = self.stringtype_addr
        #addr = 0x0049A220
        for i in idautils.DataRefsTo(addr):
            stringptr_code_addr = self.is_ptr_string(i)
            if not stringptr_code_addr:
                continue
            stringptr_addr = int(idc.GetOpnd(stringptr_code_addr,1)[4:],16)
            string_addr = common.read_mem(stringptr_addr,4)
            string_length = common.read_mem(stringptr_addr+4,1)
            if self.create_string(string_addr,string_length) == False:
                common._error("create string:0x%x size:0x%x error" % (string_addr,string_length))
                continue
            strings_added = strings_added + 1
        return strings_added

    def create_string(self,string_addr,string_length):
        if idc.get_segm_name(string_addr) is None:
            return False
        # MakeUnknown
        idc.MakeUnknown(string_addr, string_length, idc.DOUNK_SIMPLE)
        # MakeString
        idc.MakeStr(string_addr,string_addr + string_length)
        return True
    
    def create_offset(self,addr):
        if idc.OpOff(addr, 1, 0):
            return True
        else:
            common._debug('Unable to make an offset for string @ 0x%x ' % addr)
        return False

    def parse(self):
        string_count = 0
        common._info("\t\t\t  parse const string start\t\t\t  ")
        string_count = string_count + self.parse_conststring()
        common._info("\t\t\t  parse const string end\t\t\t  ")
        common._info("\t\t\t  parse ptr string start\t\t\t  ")
        string_count = string_count + self.parse_ptrstring()
        common._info("\t\t\t  parse ptr string end\t\t\t  ")
        common._info("\t\t\t  %d string finished creating\t\t\t  " % string_count)

