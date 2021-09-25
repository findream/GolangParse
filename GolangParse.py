'''
GolangParse.py: help reverse golang program based IDAPython
   [*] recover the functions be stripped name 
   [*] recover the src file path
   [*] recover the type struct,include rtype ptr struct
   [*] recover const string and ptr string

author：HaCky

version：GolangParse V1.1

operating platform：IDA 7.5 Python 3.8

target golang version：go 1.15 x86 PE

reference：
    https://github.com/0xjiayu/go_parser
    https://github.com/strazzere/golang_loader_assist/blob/ad20e82e0fa55f25cfb026505703c60a29432646/golang_loader_assist.py
'''


#encoding = utf-8
import idc
import idautils
import idaapi
import pclntbl
import common
import moduledata
import type_builder
import string_builder
idaapi.require("pclntbl")
idaapi.require("common")
idaapi.require("moduledata")
idaapi.require("type_builder")
idaapi.require("string_builder")

def main_windows():
    breakpoint()
    # find_first_moduledata_addr
    first_moduledata_addr = moduledata.get_first_moduledata_addr()

    if first_moduledata_addr == idc.BADADDR:
        common._error("first_moduledata_addr is BADADDR")
        return 

    # parse first moduledata
    first_moduledata = moduledata.ModuleData(first_moduledata_addr)
    first_moduledata.parse()

    # parse pclntable struct
    # pclntable address in first_moduledata
    pclntable = pclntbl.Pclntbl(first_moduledata.pclntbl_addr,first_moduledata.filetab_addr)
    pclntable.parse()

    #type
    typeparse = type_builder.TypeParse(first_moduledata)
    typeparse.build_all_types()

    # send typeparse.stringtype_addr to
    stringparse = string_builder.StringParse(typeparse.stringtype_addr)
    stringparse.parse()

    common._info("\t\t\t  ----->finish")
    common._info("\t\t\t  ----->pclntbl finish")
    common._info("\t\t\t  ----->pclntbl addr:0x%x" % first_moduledata.pclntbl_addr)
    common._info("\t\t\t  ----->function finish")
    common._info("\t\t\t  ----->srcfile finish")
    common._info("\t\t\t  ----->type finish")
    common._info("\t\t\t  ----->string finish")
    


def main_linux():
    breakpoint()
    first_moduledata_addr = moduledata.get_first_moduledata_addr()
    if first_moduledata_addr == idc.BADADDR:
        _error("first_moduledata_addr is BADADDR")
        return
         
    # parse first moduledata
    first_moduledata = moduledata.ModuleData(first_moduledata_addr)
    first_moduledata.parse()

    # parse pclntable struct
    # pclntable address in first_moduledata
    pclntable = pclntbl.Pclntbl(first_moduledata.pclntbl_addr,first_moduledata.filetab_addr)
    pclntable.parse()

    

def main():
    if "Portable executable" in idaapi.get_file_type_name():
        main_windows()
    elif "ELF" in idaapi.get_file_type_name():
        main_linux()

if __name__ == '__main__':
    main()


# STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
# REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
# # clean bad char of function name
# def clean_function_name(name_str):
#     '''
#     Clean generic 'bad' characters
#     '''
#     #name_str = filter(lambda x: x in string.printable, name_str)
#     name_str = name_str.decode("ascii","replace").split(' ',1)[0]

#     for c in STRIP_CHARS:
#         name_str = name_str.replace(c, '')
        

#     for c in REPLACE_CHARS:
#         name_str = name_str.replace(c, '_')
#     return name_str

# def _error(err_str):
#     print('\t\t\t  [ERROR] - %s' % err_str)

# def _info(info_str):
#     print(info_str)

# def read_mem(addr,size):
#     if size == 1:
#         return idc.get_wide_byte(addr)
#     if size == 2:
#         return idc.get_wide_word(addr)
#     if size == 4:
#         return idc.get_wide_dword(addr)
#     if size ==8:
#         return idc.get_qword(addr)

# def funcparse(pclntbl_addr):
#     ptr_sz = 8
#     func_num = read_mem(pclntbl_addr+8,8) 
#     idc.MakeDword(pclntbl_addr+8)
#     idc.MakeComm(pclntbl_addr+8,"Number of Functions")
#     idc.MakeNameEx(pclntbl_addr+8,"func_tbl_entry",flags=idaapi.SN_FORCE)    

#     # func_tbl_entry
#     funcs_tbl_entry = pclntbl_addr + 8
    
#     # func_tbl_addr
#     func_tbl_addr = funcs_tbl_entry + 8

#     # func_tbl_sz
#     func_tbl_sz = func_num * 8 * 2

#     for func_id in range(func_num):
#         func_name_addr = func_tbl_addr + ptr_sz * func_id * 2
#         func_name_offset = read_mem(func_name_addr + ptr_sz,8)
#         func_struct_addr = pclntbl_addr + func_name_offset
#         funcstruct = FuncStruct1(func_struct_addr,pclntbl_addr)
#         funcstruct.parse()
#         _info("\t\t\t parse func:%s finished " % funcstruct.name)
#         del funcstruct
#     _info("\t\t\t  parse func end\t\t\t  ")

# class FuncStruct1():
#     def __init__(self,addr,pclntbl):
#         self.pclntbl = pclntbl
#         self.addr = addr       # func struct address
#         self.entry = 0
#         self.name = ""
#         self.args = 0
#         self.frame = 0
#         self.pcsp = 0
#         self.pcfile = 0
#         self.pcln = 0
#         self.nfuncdata = 0
#         self.npcdata = 0
    
#     def parse(self):
#         # func_addr
#         self.entry = read_mem(self.addr,8)
#         ptr_sz = 8
        
#         # func_name
#         name_offset = read_mem(self.addr + ptr_sz , 4)
#         funcname = idc.GetString(self.pclntbl + name_offset)
#         if funcname:
#             self.name = clean_function_name(funcname)
#             #self.name = funcname
        
#         if len(self.name) > 100:
#             print(self.pclntbl + name_offset)
#         # func_args
#         self.args = read_mem(self.addr + ptr_sz *2 , ptr_sz )

#         # func_frame
#         self.frame = read_mem(self.addr + ptr_sz *3 , ptr_sz )

#         # func_pcsp
#         self.pcsp = read_mem(self.addr + ptr_sz *4 , ptr_sz)

#         # func_pcfile 
#         self.pcfile = read_mem(self.addr + ptr_sz*5 , ptr_sz)

#         # func_pcln
#         self.pcln = read_mem(self.addr + ptr_sz*6 , ptr_sz)

#         # func_nfuncdata 
#         self.nfuncdata = read_mem(self.addr + ptr_sz*7 , ptr_sz)

#         # func_npdata
#         self.npcdata = read_mem(self.addr + ptr_sz*8 , ptr_sz)


#         # func struct address
#         idc.MakeComm(self.addr, "Func Entry")

#         # func_struct.nameoffset
#         idc.MakeDword(self.addr + ptr_sz)
#         idc.MakeComm(self.addr + ptr_sz,"Func name offset(Addr @ 0x%x), name string: %s" % (self.pclntbl + name_offset, self.name))

#         # Make string of funcname 
#         idc.MakeUnknown(self.pclntbl + name_offset,len(self.name)+1,idc.DOUNK_SIMPLE)
#         if not idc.MakeStr(self.pclntbl + name_offset, self.pclntbl+ name_offset + len(self.name)+1):
#             _error("Make func_name_str [%s] failed @0x%x" % (self.name, self.pclntbl + name_offset))

#         # Rename function
#         real_func_addr = idaapi.get_func(self.entry)
#         if len(self.name) !=0 and real_func_addr:
#             if not idc.MakeNameEx(real_func_addr.startEA,self.name,flags=idaapi.SN_FORCE):
#                 _error("Failed to rename function @ 0x%x" % real_func_addr.startEA)
        
#         # Handle func_args
#         idc.MakeDword(self.addr + ptr_sz*2)
#         idc.MakeComm(self.addr + ptr_sz*2,"args")

#         # Handle func_frame
#         idc.MakeDword(self.addr + ptr_sz*3)
#         idc.MakeComm(self.addr + ptr_sz*3,"frame")

#         # Handle func_pcsp
#         idc.MakeDword(self.addr + ptr_sz*4)
#         idc.MakeComm(self.addr + ptr_sz*4,"pcsp")

#         # Handle func_pcfile
#         idc.MakeDword(self.addr + ptr_sz*5)
#         idc.MakeComm(self.addr + ptr_sz*5,"pcfile")

#         # Handle func_pcln
#         idc.MakeDword(self.addr + ptr_sz*6)
#         idc.MakeComm(self.addr + ptr_sz*6,"pcln")

#         # Handle func_nfuncdata 
#         idc.MakeDword(self.addr + ptr_sz*7)
#         idc.MakeComm(self.addr + ptr_sz*7,"nfuncdata")

#         # Handle func_npdata
#         idc.MakeDword(self.addr + ptr_sz*8)
#         idc.MakeComm(self.addr + ptr_sz*8,"npdata")