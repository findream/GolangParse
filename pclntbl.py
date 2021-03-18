#encoding = utf-8
import idc
import idautils
import idaapi
idaapi.require("common")

class Pclntbl():
    MAGIC = 0xFFFFFFFB
    def __init__(self,pclntbl_addr,filetab_addr):
        self.start_addr = pclntbl_addr
        self.min_lc = 0             # instruction size quantum
        self.ptr_sz = 0             # size in bytes of pointers(x64 or x86)
        self.func_num = 0           # number of funuction
        self.func_tbl_addr = idc.BADADDR    # func table address 
        self.func_tbl_sz = 0        # Size of whole function table

        self.srcfile_tbl_addr = filetab_addr
        self.srcfile_num = 0 # Number of src files
        self.srcfiles = list()
    
    def parse_hdr(self):
        common._info("\t\t\t  parse pclntab header start\t\t\t  ")
        # Determine whether it is a valid Magic Word
        if common.read_mem(self.start_addr,4) != Pclntbl.MAGIC:
            common._error("Invalid pclntbl header magic number!")
            idc.Exit(1)
        idc.MakeDword(self.start_addr)
        idc.MakeComm(self.start_addr, "Magic Number")
        idc.MakeNameEx(self.start_addr, "runtime_symtab", flags=idaapi.SN_FORCE)

        if common.read_mem(self.start_addr+4,2) != 0:
            common._error("Invalid pclntbl header")
        idc.MakeWord(self.start_addr+4)

        # min_lc
        self.min_lc = common.read_mem(self.start_addr+6,1) 
        idc.MakeByte(self.start_addr+6)
        idc.MakeComm(self.start_addr+6,"instruction size quantum")

        # ptr_sz
        self.ptr_sz = common.read_mem(self.start_addr+7,1) 
        idc.MakeByte(self.start_addr+7)
        idc.MakeComm(self.start_addr+7,"size of uintptr")
        common._info("\t\t\t  parse pclntab header end\t\t\t  ")



    def parse_func(self):
        common._info("\t\t\t  parse func start\t\t\t  ")
        # func_num
        self.func_num = common.read_mem(self.start_addr+8,4) 
        idc.MakeDword(self.start_addr+8)
        idc.MakeComm(self.start_addr+8,"Number of Functions")
        idc.MakeNameEx(self.start_addr+8,"func_tbl_entry",flags=idaapi.SN_FORCE)

        # func_tbl_entry
        funcs_tbl_entry = self.start_addr + 8
        
        # func_tbl_addr
        self.func_tbl_addr = funcs_tbl_entry + self.ptr_sz

        # func_tbl_sz
        self.func_tbl_sz = self.func_num * self.ptr_sz * 2

        # Traverse func_tbl to parse func name and func struct address
        # Located by func_id
        # func_name_addr = func_tbl_addr + 2 * self.ptr_sz * func_id
        # func_name_offset = func_tbl_addr + 2 * self.ptr_sz * func_id
        for func_id in range(self.func_num):
            func_name_addr = self.func_tbl_addr + self.ptr_sz * func_id * 2
            func_name_offset = common.read_mem(func_name_addr + self.ptr_sz,4)
            func_struct_addr = self.start_addr + func_name_offset
            funcstruct = FuncStruct(func_struct_addr,self)
            funcstruct.parse()
            common._info("\t\t\t parse func:%s finished " % funcstruct.name)
            del funcstruct
        common._info("\t\t\t  parse func end\t\t\t  ")
    
    def parse_src(self):
        common._info("\t\t\t  parse srcfile start\t\t\t  ")
        if self.srcfile_tbl_addr != self.start_addr + common.read_mem(self.func_tbl_addr + self.func_tbl_sz + self.ptr_sz,4):
            common._error("scrfile table address is error")
        
        srcfile_tbl_addr = self.srcfile_tbl_addr 
        # srcfile_tbl_offset
        idc.MakeComm(self.func_tbl_addr + self.func_tbl_sz + self.ptr_sz,"Source file table addr:0x%x" % self.srcfile_tbl_addr)

        # rename scrfile_tbl
        idc.MakeNameEx(srcfile_tbl_addr,"runtime_srcfiletab",flags=idaapi.SN_FORCE)

        # srcfile path number
        self.srcfile_num = common.read_mem(srcfile_tbl_addr,4)-1
        idc.MakeComm(srcfile_tbl_addr,"scrfile_num")

        # traverse all srcfile 
        start_addr = srcfile_tbl_addr + self.ptr_sz
        for src_id in range(self.srcfile_num):
            curr_addr = start_addr + src_id * self.ptr_sz
            srcfile_offset = common.read_mem(curr_addr,4)
            srcfile_addr = self.start_addr + srcfile_offset
            idc.MakeDword(curr_addr)
            #idc.MakeComm(curr_addr,"srcfile_addr:0x%x" % srcfile_addr)

            # srcfile path
            srcfile_path = idc.GetString(srcfile_addr).decode("ascii","replace")
            if not srcfile_path:
                common._error("Failed to parse 0x%x scrfile"%srcfile_addr)
                continue
            idc.MakeStr(srcfile_addr,srcfile_addr + len(srcfile_path)+1)
            idaapi.add_dref(curr_addr,srcfile_addr,idaapi.dr_O)
        common._info("\t\t\t  parse srcfile end\t\t\t  ")








    def parse(self):
        self.parse_hdr()
        self.parse_func()
        self.parse_src()


'''
struct Func
{
    uintptr      entry;     // start pc
    int32        name;      // name (offset to C string)
    int32        args;      // size of arguments passed to function
    int32        frame;     // size of function frame, including saved caller PC
    int32        pcsp;      // pcsp table (offset to pcvalue table)
    int32        pcfile;    // pcfile table (offset to pcvalue table)
    int32        pcln;      // pcln table (offset to pcvalue table)
    int32        nfuncdata; // number of entries in funcdata list
    int32        npcdata;   // number of entries in pcdata list
};
'''

class FuncStruct():
    def __init__(self,addr,pclntbl):
        self.pclntbl = pclntbl
        self.addr = addr       # func struct address
        self.entry = 0
        self.name = ""
        self.args = 0
        self.frame = 0
        self.pcsp = 0
        self.pcfile = 0
        self.pcln = 0
        self.nfuncdata = 0
        self.npcdata = 0
    
    def parse(self):
        # func_addr
        self.entry = common.read_mem(self.addr,4)
        
        # func_name
        name_offset = common.read_mem(self.addr + self.pclntbl.ptr_sz , self.pclntbl.ptr_sz)
        funcname = idc.GetString(self.pclntbl.start_addr + name_offset)
        if funcname:
            self.name = common.clean_function_name(funcname)
            #self.name = funcname
        
        if len(self.name) > 100:
            print(self.pclntbl.start_addr + name_offset)
        # func_args
        self.args = common.read_mem(self.addr + self.pclntbl.ptr_sz*2 , self.pclntbl.ptr_sz)

        # func_frame
        self.frame = common.read_mem(self.addr + self.pclntbl.ptr_sz*3 , self.pclntbl.ptr_sz)

        # func_pcsp
        self.pcsp = common.read_mem(self.addr + self.pclntbl.ptr_sz*4 , self.pclntbl.ptr_sz)

        # func_pcfile 
        self.pcfile = common.read_mem(self.addr + self.pclntbl.ptr_sz*5 , self.pclntbl.ptr_sz)

        # func_pcln
        self.pcln = common.read_mem(self.addr + self.pclntbl.ptr_sz*6 , self.pclntbl.ptr_sz)

        # func_nfuncdata 
        self.nfuncdata = common.read_mem(self.addr + self.pclntbl.ptr_sz*7 , self.pclntbl.ptr_sz)

        # func_npdata
        self.npcdata = common.read_mem(self.addr + self.pclntbl.ptr_sz*8 , self.pclntbl.ptr_sz)


        # func struct address
        idc.MakeComm(self.addr, "Func Entry")

        # func_struct.nameoffset
        idc.MakeDword(self.addr + self.pclntbl.ptr_sz)
        idc.MakeComm(self.addr + self.pclntbl.ptr_sz,"Func name offset(Addr @ 0x%x), name string: %s" % (self.pclntbl.start_addr + name_offset, self.name))

        # Make string of funcname 
        idc.MakeUnknown(self.pclntbl.start_addr + name_offset,len(self.name)+1,idc.DOUNK_SIMPLE)
        if not idc.MakeStr(self.pclntbl.start_addr + name_offset, self.pclntbl.start_addr + name_offset + len(self.name)+1):
            common._error("Make func_name_str [%s] failed @0x%x" % (self.name, self.pclntbl.start_addr + name_offset))

        # Rename function
        real_func_addr = idaapi.get_func(self.entry)
        if len(self.name) !=0 and real_func_addr:
            if not idc.MakeNameEx(real_func_addr.startEA,self.name,flags=idaapi.SN_FORCE):
                common._error("Failed to rename function @ 0x%x" % real_func_addr.startEA)
        
        # Handle func_args
        idc.MakeDword(self.addr + self.pclntbl.ptr_sz*2)
        idc.MakeComm(self.addr + self.pclntbl.ptr_sz*2,"args")

        # Handle func_frame
        idc.MakeDword(self.addr + self.pclntbl.ptr_sz*3)
        idc.MakeComm(self.addr + self.pclntbl.ptr_sz*3,"frame")

        # Handle func_pcsp
        idc.MakeDword(self.addr + self.pclntbl.ptr_sz*4)
        idc.MakeComm(self.addr + self.pclntbl.ptr_sz*4,"pcsp")

        # Handle func_pcfile
        idc.MakeDword(self.addr + self.pclntbl.ptr_sz*5)
        idc.MakeComm(self.addr + self.pclntbl.ptr_sz*5,"pcfile")

        # Handle func_pcln
        idc.MakeDword(self.addr + self.pclntbl.ptr_sz*6)
        idc.MakeComm(self.addr + self.pclntbl.ptr_sz*6,"pcln")

        # Handle func_nfuncdata 
        idc.MakeDword(self.addr + self.pclntbl.ptr_sz*7)
        idc.MakeComm(self.addr + self.pclntbl.ptr_sz*7,"nfuncdata")

        # Handle func_npdata
        idc.MakeDword(self.addr + self.pclntbl.ptr_sz*8)
        idc.MakeComm(self.addr + self.pclntbl.ptr_sz*8,"npdata")



        




        





    




            











