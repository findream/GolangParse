#coding = utf-8
import idc
import idautils
import idaapi
idaapi.require("common")

class TypeParse():
    def __init__(self,first_moduledata):
        self.first_moduledata = first_moduledata

    def build_all_types(self):
        common._info("-----------------------build_all_types start-----------------------")
        typelink_addr = self.first_moduledata.typelink_addr
        type_num = self.first_moduledata.type_num
        for type_id in range(type_num):
            curr_addr = typelink_addr + type_id * 4
            eachtype_offset = common.read_mem(curr_addr,4)
            eachtype_addr = self.first_moduledata.types_addr + eachtype_offset
            idc.MakeDword(curr_addr)
            idc.MakeComm(curr_addr,"type @ 0x%x" % eachtype_addr)
            self.parse_type(eachtype_addr)
        common._info("-----------------------build_all_types end-----------------------")


    def parse_type(self,eachtype_addr):
        rtype = RType(eachtype_addr,self)
        rtype.parse()

        # Ptr Type
        if RType.TYPE_KINDS[rtype.kind & RType.KIND_MASK] == "Ptr":
            ptrtype = PtrType(rtype.addr+0x20,rtype)
            ptrtype.parse()

        
        # Struct Type
        if RType.TYPE_KINDS[rtype.kind & RType.KIND_MASK] == "Struct":
            structtype = StructType(rtype)
            structtype.parse()


'''
TypeParse--->RType
'''
class RType():
    '''
    // Refer: https://golang.org/src/reflect/type.go
    type rtype struct {
        size       uintptr
        ptrdata    uintptr  // number of bytes in the type that can contain pointers
        hash       uint32   // hash of type; avoids computation in hash tables
        tflag      tflag    // extra type information flags
        align      uint8    // alignment of variable with this type
        fieldAlign uint8    // alignment of struct field with this type
        kind       uint8    // enumeration for C
        alg        *typeAlg // algorithm table
        gcdata     *byte    // garbage collection data
        str        nameOff  // string form
        ptrToThis  typeOff  // type for pointer to this type, may be zero
    }
    '''
    # Refer: https://golang.org/pkg/reflect/#Kind
    TYPE_KINDS = ['Invalid Kind','Bool','Int','Int8','Int16','Int32','Int64','Uint','Uint8','Uint16','Uint32','Uint64','Uintptr','Float32','Float64','Complex64','Complex128','Array','Chan','Func','Interface','Map','Ptr','Slice','String','Struct','UnsafePointer']
    KIND_MASK  = (1 << 5) - 1
    def __init__(self,addr,type_parser):
        self.addr = addr
        self.type_parser = type_parser
        #self.first_moduledata = type_parser.first_moduledata
        self.size = 0
        self.ptrdata = 0
        self.hash = None
        self.tflag = None
        self.align = 0
        self.field_align = 0
        self.kind = 0
        self.alg = None
        self.gcdata = None
        self.name_off = 0
        self.name_addr = idc.BADADDR
        self.ptrtothis = None
        self.Name = None

    def parse(self):
        # rtype.size
        self.size = common.read_mem(self.addr, 4)
        idc.MakeDword(self.addr)
        idc.MakeComm(self.addr, "rtype.size")
        # TODO:记得改一下名字

        # rtype.ptrdata
        self.ptrdata = common.read_mem(self.addr+4, 4)
        idc.MakeDword(self.addr + 4)
        idc.MakeComm(self.addr + 4, "rtype.ptrdata")

        # rtype.hash
        self.hash = common.read_mem(self.addr+4*2, 4)
        idc.MakeDword(self.addr + 4*2)
        idc.MakeComm(self.addr + 4*2, "rtype.hash")

        # rtype.tflag
        self.tflag = common.read_mem(self.addr+4*3, 1)
        tflag_comm = "rtype.tflag:"
        if self.tflag & 1 !=0:
            tflag_comm = tflag_comm + " star prefix;"
        if self.tflag & 2 !=0:
            tflag_comm = tflag_comm + " named;"
        if self.tflag & 4 !=0:
            tflag_comm = tflag_comm + " Uncommon"
        idc.MakeComm(self.addr + 4*3, tflag_comm)      

        # rtype.align
        self.align = common.read_mem(self.addr+4*3+1, 1)
        idc.MakeComm(self.addr + 4*3+1, "rtype.align")

        # rtype.field_align
        self.field_align = common.read_mem(self.addr+4*3+2, 1)
        idc.MakeComm(self.addr + 4*3+2, "rtype.field_align")

        # rtype.kind
        self.kind = common.read_mem(self.addr+4*3+3, 1)
        idc.MakeComm(self.addr + 4*3+3, "rtype.kind:" + RType.TYPE_KINDS[self.kind & RType.KIND_MASK])


        # rtype.alg
        self.alg = common.read_mem(self.addr+4*4, 4)
        idc.MakeDword(self.addr + 4*4)
        idc.MakeComm(self.addr + 4*4, "rtype.alg")
        
        # rtpe.gcdata
        self.gcdata = common.read_mem(self.addr+4*5, 4)
        idc.MakeDword(self.addr + 4*5)
        idc.MakeComm(self.addr + 4*5, "rtype.gcdata")

        # rtype.name_off 
        self.name_off = common.read_mem(self.addr+4*6, 4)
        idc.MakeDword(self.addr + 4*6)
        self.name_addr = self.type_parser.first_moduledata.types_addr + self.name_off
        name = Name(self)
        name.parse()

        # rtype.ptrtothis
        self.ptrtothis = common.read_mem(self.addr+4*7, 4)
        idc.MakeDword(self.addr+4*7)
        idc.MakeComm(self.addr + 4*7,"rtype.ptrtothis")

        # Get Name Class
        self.Name = name


            




'''
RType ---> Name
      ---> Struct
      --->
      --->
      --->
'''
class Name():
    '''
    type Name struct
    {
        flag
        length
        name_string
    }
    '''
    MASK_EXPORTED = 0x1
    MASK_FOLLOWED_BY_TAG = 0x2
    MASK_FOLLOWED_BY_PKGPATH = 0x4
    def __init__(self,rtype):
        self.rtype = rtype
        self.name_addr = rtype.name_addr
        self.flag = 0
        self.length = 0
        self.name_str = ""


    def parse(self):
        # name.flag
        flag_comm_str = "flag: "
        self.flag = common.read_mem(self.name_addr, 2)
        if self.flag & Name.MASK_EXPORTED !=0:
            flag_comm_str = flag_comm_str + "exported "
        if self.flag & Name.MASK_FOLLOWED_BY_TAG !=0:
            flag_comm_str = flag_comm_str + "followed by tag "
        if self.flag & Name.MASK_FOLLOWED_BY_PKGPATH !=0:
            flag_comm_str = flag_comm_str + "followed by pkgpath "
        idc.MakeComm(self.name_addr,flag_comm_str)
        idc.MakeWord(self.name_addr)

        
        # name.length
        self.length = common.read_mem(self.name_addr+2, 1)
        idc.MakeComm(self.name_addr+2, "name.length:0x%x" % self.length)

        # name.name_str
        # The length of the string is known,
        # use idc.MakeString will add '0' to the end of sting  
        self.name_str = idc.GetManyBytes(self.name_addr + 3, self.length).decode("ascii","replace")
        if len(self.name_str) > 0:
            idc.MakeStr(self.name_addr + 3,self.name_addr + self.length + 3)

        # change name
        idc.MakeNameEx(self.rtype.addr,self.name_str,flags=idaapi.SN_FORCE)

        # MakeComm
        idc.MakeComm(self.rtype.addr + 4*6, "rtype.nameof(@ 0x%x):%s"%(self.name_addr,self.name_str))

class PtrType():
    def __init__(self,ptr_addr,rtype):
        self.ptr_addr = ptr_addr
        self.rtype = rtype
    
    def parse(self):
        common._info("-----------------------Ptr:%s start-----------------------" % self.rtype.Name.name_str)
        ptrtype_addr = common.read_mem(self.ptr_addr,4)
        type_ptr = RType(ptrtype_addr,self.rtype.type_parser)
        type_ptr.parse()
        common._info("-----------------------Ptr:%s end-----------------------" % self.rtype.Name.name_str)


class StructType():
    '''
    type structType struct 
    {
        rtype
        pkgPath name          
        fields  []structField 
    }
    '''
    def __init__(self,rtype):
        self.rtype_pkgpath_addr = rtype.addr+0x20
        self.pkgpath_addr = 0
        self.pkgpath = ""
        self.rtype_structField_addr = rtype.addr+0x24
        self.structField_addr = 0
        self.rtype = rtype


    def parse(self):
        common._info("-----------------------Struct:%s start-----------------------" % self.rtype.Name.name_str)
        self.parse_pkgpath()
        idc.MakeComm(self.rtype_pkgpath_addr,"rtype.pkgpath @0x%x" % self.pkgpath_addr)

        self.parse_fields()
        idc.MakeComm(self.rtype_structField_addr,"rtype.structField @0x%x" % self.structField_addr)
        common._info("-----------------------Struct:%s end-----------------------" % self.rtype.Name.name_str)
    
    def parse_pkgpath(self):
        # pkgpath
        self.pkgpath_addr = common.read_mem(self.rtype_pkgpath_addr,4)

        # flag
        flag = common.read_mem(self.pkgpath_addr, 2)

        idc.Word(self.pkgpath_addr)
        idc.MakeComm(self.pkgpath_addr, "pkgpath.flag")

        # length
        length = common.read_mem(self.pkgpath_addr + 2, 1)
        idc.MakeComm(self.pkgpath_addr+2, "pkgpath.length 0x%x" % length)

        # pkgpath         
        self.pkgpath = idc.GetManyBytes(self.pkgpath_addr + 3, length).decode("ascii","replace")
        if len(self.pkgpath) > 0:
            idc.MakeStr(self.pkgpath_addr + 3 + 3,self.pkgpath_addr + 3 + length + 3)

        # rename
        idc.MakeNameEx(self.pkgpath_addr,self.pkgpath,flags=idaapi.SN_FORCE)

    def parse_fields(self):
        self.structField_addr = common.read_mem(self.rtype_structField_addr,4)

        # name
        fields_name_addr = common.read_mem(self.structField_addr,4)
        fields_name = ParseString(fields_name_addr)
        fields_name.getflag()
        fields_name.getlength()
        fields_name.getvalue()
        idc.MakeComm(fields_name.flag_addr,"fields_name flag")
        idc.MakeComm(fields_name.length_addr,"fields_name length:0x%x" % fields_name.string_length)
        idc.MakeNameEx(fields_name_addr,fields_name.string_value,flags=idaapi.SN_FORCE)

        # structfields.rtype
        idc.MakeComm(self.structField_addr+4, "fields.rtype")

        # structfields.offsetEmbed
        idc.MakeComm(self.structField_addr+8, "fields.offsetEmbed")



# parse string
'''
    type string struct
    {
        flag
        length
        string_value
    }
'''
class ParseString():
    def __init__(self,string_addr):
        self.string_addr = string_addr
        self.flag_addr = 0
        self.length_addr = 0
        self.value_addr = 0
        self.string_flag = 0
        self.string_length = 0
        self.string_value = ""

    def getflag(self):
        self.flag_addr = self.string_addr
        self.string_flag = common.read_mem(self.string_addr,2)
        idc.MakeWord(self.flag_addr)

    def getlength(self):
        self.length_addr = self.string_addr + 2
        self.string_length = common.read_mem(self.string_addr+2,1)

    def getvalue(self):
        self.value_addr = self.string_addr + 3
        self.string_value = idc.GetManyBytes(self.value_addr,self.string_length).decode("ascii","replace")
        if len(self.string_value) > 0:
            idc.MakeStr(self.value_addr, self.value_addr + self.string_length)
        





        




        








    


