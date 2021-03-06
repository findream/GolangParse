#encoding = utf-8
import idc
import idautils
import idaapi
idaapi.require("pclntbl")
idaapi.require("common")
idaapi.require("moduledata")

def main():
    breakpoint()
    # find_first_moduledata_addr
    first_moduledata_addr = moduledata.get_first_moduledata_addr()

    # parse first moduledata
    first_moduledata = moduledata.ModuleData(first_moduledata_addr)
    first_moduledata.parse()

    # parse pclntable struct
    # pclntable address in first_moduledata
    pclntable = pclntbl.Pclntbl(first_moduledata.pclntbl_addr,first_moduledata.srcfile_tbl_addr)
    pclntable.parse()

if __name__ == '__main__':
    main()