#encoding = utf-8
import idc
import idautils
import idaapi

ADDR_SZ = 4

'''
type moduledata struct {
    pclntable    []byte
    ftab         []functab
    filetab      []uint32
    findfunctab  uintptr
    minpc, maxpc uintptr

    text, etext           uintptr
    noptrdata, enoptrdata uintptr
    data, edata           uintptr
    bss, ebss             uintptr
    noptrbss, enoptrbss   uintptr
    end, gcdata, gcbss    uintptr
    types, etypes         uintptr

    textsectmap []textsect
    typelinks   []int32 // offsets from types
    itablinks   []*itab

    ptab []ptabEntry

    pluginpath string
    pkghashes  []modulehash

    modulename   string
    modulehashes []modulehash

    hasmain uint8 // 1 if module contains the main function, 0 otherwise

    gcdatamask, gcbssmask bitvector

    typemap map[typeOff]*_type // offset to *_rtype in previous module

    bad bool // module failed to load and should be ignored

    next *moduledata
}
'''


class ModuleData():
    def __init__(self, start_addr):
        self.start_addr = start_addr
        self.pclntbl_addr = idc.BADADDR
        self.pclntbl_sz = 0
        self.pclntbl_cap = 0
        self.ftab_addr = idc.BADADDR
        self.func_num = 0
        self.ftab_cap = 0
        self.filetab_addr = idc.BADADDR
        self.srcfile_num = 0
        self.srcfile_tab_cap = 0
        self.findfunctab = idc.BADADDR
        self.min_pc = idc.BADADDR
        self.max_pc = idc.BADADDR
        self.text_addr = idc.BADADDR
        self.etext_addr = idc.BADADDR
        self.noptrdata_addr = idc.BADADDR
        self.enoptrdata_addr = idc.BADADDR
        self.data_addr = idc.BADADDR
        self.edata_addr = idc.BADADDR
        self.bss_addr = idc.BADADDR
        self.ebss_addr = idc.BADADDR
        self.noptrbss_addr = idc.BADADDR
        self.enoptrbss_addr = idc.BADADDR
        self.end_addr = idc.BADADDR
        self.gcdata_addr = idc.BADADDR
        self.gcbss_addr = idc.BADADDR
        self.types_addr = idc.BADADDR
        self.etypes_addr = idc.BADADDR
        self.textsecmap_addr = idc.BADADDR
        self.textsecmap_len = 0
        self.textsecmap_cap = 0
        self.typelink_addr = idc.BADADDR
        self.type_num = 0
        self.type_cap = 0
        self.itablink_addr = idc.BADADDR
        self.itab_num = 0
        self.itab_cap = 0
        self.ptab_addr = idc.BADADDR
        self.ptab_num = 0
        self.ptab_cap = 0
        self.pluginpath = ""
        self.modulename = ""
        self.hasmain = False
        self.next = idc.BADADDR
    
    def parse(self):
        self.start_addr = self.start_addr
        self.pclntbl_addr = read_mem(self.start_addr , 4)
        self.pclntbl_sz = read_mem(self.start_addr + ADDR_SZ , 4)
        self.pclntbl_cap = read_mem(self.start_addr + 2*ADDR_SZ , 4)
        self.ftab_addr = read_mem(self.start_addr + 3*ADDR_SZ , 4)
        self.func_num = read_mem(self.start_addr + 4*ADDR_SZ , 4)
        self.ftab_cap = read_mem(self.start_addr + 5*ADDR_SZ , 4)
        self.filetab_addr = read_mem(self.start_addr + 6*ADDR_SZ , 4)
        self.srcfile_num = read_mem(self.start_addr + 7*ADDR_SZ , 4)
        self.srcfile_tab_cap = read_mem(self.start_addr + 8*ADDR_SZ , 4)
        self.findfunctab = read_mem(self.start_addr + 9*ADDR_SZ , 4)
        self.min_pc = read_mem(self.start_addr + 10*ADDR_SZ , 4)
        self.max_pc = read_mem(self.start_addr + 11*ADDR_SZ , 4)
        self.text_addr = read_mem(self.start_addr + 12*ADDR_SZ , 4)
        self.etext_addr = read_mem(self.start_addr + 13*ADDR_SZ , 4)
        self.noptrdata_addr = read_mem(self.start_addr + 14*ADDR_SZ , 4)
        self.enoptrdata_addr = read_mem(self.start_addr + 15*ADDR_SZ , 4)
        self.data_addr = read_mem(self.start_addr + 16*ADDR_SZ , 4)
        self.edata_addr = read_mem(self.start_addr + 17*ADDR_SZ , 4)
        self.bss_addr = read_mem(self.start_addr + 18*ADDR_SZ , 4)
        self.ebss_addr = read_mem(self.start_addr + 19*ADDR_SZ , 4)
        self.noptrbss_addr = read_mem(self.start_addr + 20*ADDR_SZ , 4)
        self.enoptrbss_addr = read_mem(self.start_addr + 21*ADDR_SZ , 4)
        self.end_addr = read_mem(self.start_addr + 22*ADDR_SZ , 4)
        self.gcdata_addr = read_mem(self.start_addr + 23*ADDR_SZ , 4)
        self.gcbss_addr = read_mem(self.start_addr + 24*ADDR_SZ , 4)
        self.types_addr = read_mem(self.start_addr + 25*ADDR_SZ , 4)
        self.etypes_addr = read_mem(self.start_addr + 26*ADDR_SZ , 4)
        self.textsecmap_addr = read_mem(self.start_addr + 27*ADDR_SZ , 4)
        self.textsecmap_len = read_mem(self.start_addr + 28*ADDR_SZ , 4)
        self.textsecmap_cap = read_mem(self.start_addr + 29*ADDR_SZ , 4)
        self.typelink_addr = read_mem(self.start_addr + 30*ADDR_SZ , 4)
        self.type_num = read_mem(self.start_addr + 31*ADDR_SZ , 4)
        self.type_cap = read_mem(self.start_addr + 32*ADDR_SZ , 4)
        self.itablink_addr = read_mem(self.start_addr + 33*ADDR_SZ , 4)
        self.itab_num = read_mem(self.start_addr + 34*ADDR_SZ , 4)
        self.itab_cap = read_mem(self.start_addr + 35*ADDR_SZ , 4)
        self.ptab_addr = read_mem(self.start_addr + 36*ADDR_SZ , 4)
        self.ptab_num = read_mem(self.start_addr + 37*ADDR_SZ , 4)
        self.ptab_cap = read_mem(self.start_addr + 38*ADDR_SZ , 4)

        pluginpath_addr = read_mem(self.start_addr + 39*ADDR_SZ , 4)
        pluginpath_len = read_mem(self.start_addr + 40*ADDR_SZ , 4)
        self.pluginpath = str(idc.GetManyBytes(pluginpath_addr, pluginpath_len))

        modulename_addr = read_mem(self.start_addr+44*ADDR_SZ , 4)
        modulename_len = read_mem(self.start_addr+45*ADDR_SZ , 4)
        self.modulename = str(idc.GetManyBytes(modulename_addr, modulename_len))

        self.hasmain = read_mem(self.start_addr+49*ADDR_SZ , 4)
        self.next = read_mem(self.start_addr+54*ADDR_SZ + 1, 4)



def read_mem(addr,size):
    if size == 1:
        return idc.get_wide_byte(addr)
    if size == 2:
        return idc.get_wide_word(addr)
    if size == 4:
        return idc.get_wide_dword(addr)
    if size ==8:
        return idc.get_qword(addr)

def main():



if __name__ == '__main__':
    breakpoint()
    main()



# def is_firstmoduledata(curr_addr):
def get_first_moduledata_addr():
    curr_addr = 0x0048E000
    while curr_addr < idc.BADADDR:
        if idc.get_qword(curr_addr)&0xFFFFFFFF == 0xFFFFFFFB:
            print("ok")
        curr_addr = curr_addr + 1
    print("error")
    