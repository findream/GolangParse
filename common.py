#encoding = utf-8
import idc
import idautils
import idaapi

ADDR_SZ = 4
# get seg struct by seg_names
def get_seg(seg_names):
    seg = None
    for seg_name in seg_names:
        seg = idaapi.get_segm_by_name(seg_name)
        if seg:
            return seg
    return seg


# read memory 
def read_mem(addr,size):
    if size == 1:
        return idc.get_wide_byte(addr)
    if size == 2:
        return idc.get_wide_word(addr)
    if size == 4:
        return idc.get_wide_dword(addr)
    if size ==8:
        return idc.get_qword(addr)

# error
def _error(err_str):
    print('[ERROR] - %s' % err_str)


STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
# clean bad char of function name
def clean_function_name(name_str):
    '''
    Clean generic 'bad' characters
    '''
    #name_str = filter(lambda x: x in string.printable, name_str)

    for c in STRIP_CHARS:
        name_str = name_str.decode("ascii","replace").replace(c, '').encode("utf-8","ignore")
        

    for c in REPLACE_CHARS:
        name_str = name_str.decode("ascii","replace").replace(c, '_').encode("utf-8","ignore")
    return name_str.decode("ascii","replace")