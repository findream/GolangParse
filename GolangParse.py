'''
GolangParse.py: help reverse golang program based IDAPython
   [*] recover the functions be stripped name 
   [*] recover the src file path
   [*] recover the type struct,include rtype ptr struct
   [*] recover const string and ptr string

author：HaCky

version：GolangParse V1.1

operating platform：IDA 7.5 Python 3.8

target golang version：go 1.15

reference：
    https://github.com/0xjiayu/go_parser
    https://github.com/strazzere/golang_loader_assist/blob/ad20e82e0fa55f25cfb026505703c60a29432646/golang_loader_assist.py
'''


#encoding = utf-8
import idc
import idautils
import idaapi
idaapi.require("pclntbl")
idaapi.require("common")
idaapi.require("moduledata")
idaapi.require("type_builder")
idaapi.require("string_builder")

def main():
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
    common._info("\t\t\t  ----->function finish")
    common._info("\t\t\t  ----->srcfile finish")
    common._info("\t\t\t  ----->type finish")
    common._info("\t\t\t  ----->string finish")
    


if __name__ == '__main__':
    main()