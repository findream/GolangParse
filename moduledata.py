#encoding = utf-8
import idc
import idautils
import idaapi
idaapi.require("pclntbl")
idaapi.require("common")
from common import ADDR_SZ,read_mem



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
    
    # parse first moduledata 
    # Use default parameters is_test = False means this is a normal parsing process, not to judge whether first_moduledata_addr is correct
    def parse(self,is_test = False):
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
        if is_test:
            return 
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

        # write first_module_data to IDA database file
        if not is_test:
            idc.MakeNameEx(self.start_addr, "runtime.firstmoduledata", flags=idaapi.SN_FORCE)
            idaapi.autoWait()

            idc.MakeComm(self.start_addr, "pclntbl addr")
            idc.MakeComm(self.start_addr + ADDR_SZ, "pclntbl size")
            idc.MakeComm(self.start_addr + 2*ADDR_SZ, "pclntbl capacity")
            idc.MakeComm(self.start_addr + 3*ADDR_SZ, "funcs table addr")
            idc.MakeComm(self.start_addr + 4*ADDR_SZ, "funcs number")
            idc.MakeComm(self.start_addr + 5*ADDR_SZ, "funcs table capacity")
            idc.MakeComm(self.start_addr + 6*ADDR_SZ, "source files table addr")
            idc.MakeComm(self.start_addr + 7*ADDR_SZ, "source files number")
            idc.MakeComm(self.start_addr + 8*ADDR_SZ, "source files table capacity")
            idc.MakeComm(self.start_addr + 9*ADDR_SZ, "findfunctable addr")
            idc.MakeComm(self.start_addr + 10*ADDR_SZ, "min pc")
            idc.MakeComm(self.start_addr + 11*ADDR_SZ, "max pc")
            idc.MakeComm(self.start_addr + 12*ADDR_SZ, "text start addr")
            idc.MakeComm(self.start_addr + 13*ADDR_SZ, "text end addr")
            idc.MakeComm(self.start_addr + 14*ADDR_SZ, "noptrdata start addr")
            idc.MakeComm(self.start_addr + 15*ADDR_SZ, "noptrdata end addr")
            idc.MakeComm(self.start_addr + 16*ADDR_SZ, "data section start addr")
            idc.MakeComm(self.start_addr + 17*ADDR_SZ, "data section end addr")
            idc.MakeComm(self.start_addr + 18*ADDR_SZ, "bss start addr")
            idc.MakeComm(self.start_addr + 19*ADDR_SZ, "bss end addr")
            idc.MakeComm(self.start_addr + 20*ADDR_SZ, "noptrbss start addr")
            idc.MakeComm(self.start_addr + 21*ADDR_SZ, "noptrbss end addr")
            idc.MakeComm(self.start_addr + 22*ADDR_SZ, "end addr of whole image")
            idc.MakeComm(self.start_addr + 23*ADDR_SZ, "gcdata addr")
            idc.MakeComm(self.start_addr + 24*ADDR_SZ, "gcbss addr")
            idc.MakeComm(self.start_addr + 25*ADDR_SZ, "types start addr")
            idc.MakeComm(self.start_addr + 26*ADDR_SZ, "types end addr")
            idc.MakeComm(self.start_addr + 27*ADDR_SZ, "test section map addr")
            idc.MakeComm(self.start_addr + 28*ADDR_SZ, "test section map length")
            idc.MakeComm(self.start_addr + 29*ADDR_SZ, "test section map capacity")
            idc.MakeComm(self.start_addr + 30*ADDR_SZ, "typelink addr")
            idc.MakeComm(self.start_addr + 31*ADDR_SZ, "types number")
            idc.MakeComm(self.start_addr + 32*ADDR_SZ, "types table capacity")
            idc.MakeComm(self.start_addr + 33*ADDR_SZ, "itabslink addr")
            idc.MakeComm(self.start_addr + 34*ADDR_SZ, "itabs number")
            idc.MakeComm(self.start_addr + 35*ADDR_SZ, "itabs caapacity")
            idc.MakeComm(self.start_addr + 36*ADDR_SZ, "ptab addr")
            idc.MakeComm(self.start_addr + 37*ADDR_SZ, "ptab num")
            idc.MakeComm(self.start_addr + 38*ADDR_SZ, "ptab capacity")
            idc.MakeComm(self.start_addr + 39*ADDR_SZ, "plugin path addr")
            idc.MakeComm(self.start_addr + 40*ADDR_SZ, "plugin path length")
            idc.MakeComm(self.start_addr + 44*ADDR_SZ, "module name addr")
            idc.MakeComm(self.start_addr + 45*ADDR_SZ, "module name length")
            idc.MakeComm(self.start_addr + 49*ADDR_SZ, "hasmain flag")
            idc.MakeComm(self.start_addr + 54*ADDR_SZ+1, "next moduledata addr")
            idaapi.autoWait()

            idc.MakeStr(modulename_addr, modulename_addr+modulename_len)
            idaapi.autoWait()
            idc.MakeStr(pluginpath_addr, pluginpath_addr+pluginpath_len)
            idaapi.autoWait()


# get .data segment address
# first_moduledata local at .data segment
def get_mdata_seg_addr():
    mdata_seg_addr = 0
    seg = None
    seg = common.get_seg([".data"])
    if seg:
        mdata_seg_addr = seg.start_ea
    return mdata_seg_addr

# judge the address getting by function get_first_moduledata_addr is correct
# [module_data.pclntbl_addr+12] == moduledata.text_addr
def is_firstmoduledata(curr_addr):
    module_data = ModuleData(curr_addr)
    module_data.parse(is_test = True)
    if read_mem(module_data.pclntbl_addr + ADDR_SZ + 8 , 4) == module_data.text_addr:
        return True
    else:
        return False
    

# get first moduledata address
# pclntable_address local at the start of first_module_data
def get_first_moduledata_addr():
    first_moduledata_addr = idc.BADADDR
    magic_num = pclntbl.Pclntbl.MAGIC

    # Because firstmoduledata is in the data section, you first need to locate the first address of the data section
    mdata_seg_addr = get_mdata_seg_addr()
    
    # Traverse the data segment to search for the signature code 0xFFFFFFFB
    curr_addr = mdata_seg_addr
    while curr_addr < idc.BADADDR:
        if idc.get_qword(read_mem(curr_addr,4))&0xFFFFFFFF == 0xFFFFFFFB:
            if is_firstmoduledata(curr_addr):
                first_moduledata_addr = curr_addr
                return first_moduledata_addr
        curr_addr = curr_addr + 1
    return first_moduledata_addr