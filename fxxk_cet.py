import idc
import idautils
from elftools.elf.elffile import ELFFile, RelocationSection
import ida_nalt
from elftools.elf.sections import Symbol

def log(x): print("[+] " + x)

def get_plt_sec():
    log("Checking cet...")
    for seg in idautils.Segments():
        if idc.SegName(seg) == '.plt.sec':
            log("CET found.")
            return seg

    return None

def resolve_func_name(funcea, rela_plt, dynsym):
    dism_addr = list(idautils.FuncItems(funcea))
    endbr = idc.GetMnem(dism_addr[0])
    assert (endbr == 'endbr64' or endbr == 'endbr32')
    jmp = dism_addr[1]
    assert(idc.GetMnem(jmp) == 'jmp')
    assert(idc.GetOpType(jmp, 0) == idc.o_mem)

    func_plt = next(idautils.DataRefsFrom(idc.GetOperandValue(jmp, 0)))
    dism_addr = list(idautils.FuncItems(func_plt))
    endbr = idc.GetMnem(dism_addr[0])
    assert (endbr == 'endbr64' or endbr == 'endbr32')
    push = dism_addr[1]
    assert(idc.GetMnem(push) == 'push')
    assert(idc.GetOpType(push, 0) == idc.o_imm)
    rela_idx = idc.GetOperandValue(push, 0)
    
    sym_idx = list(rela_plt.iter_relocations())[rela_idx].entry['r_info_sym']
    return '_' + str(dynsym.get_symbol(sym_idx).name)
    

def load_section(elf, name):
    tmp = elf.get_section_by_name(name)
    if not tmp:
        log("%s not found, this file may be damaged." % name)
        return
    log("%s found.", name)
    return tmp


def start():
    file_path = ida_nalt.get_input_file_path()
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        log("ELF file %s loaded." % file_path)
    
        plt_sec = get_plt_sec()
        if not plt_sec:
            log("No CET found, this elf does not need to recover.")
            return
    
        rela_plt = load_section(elf, ".rela.plt")
        dynsym = load_section(elf, '.dynsym')
        
        for funcea in idautils.Functions(plt_sec, idc.SegEnd(plt_sec)):
            real_name = resolve_func_name(funcea, rela_plt, dynsym)
            origin_name = idc.GetFunctionName(funcea)
            idc.MakeName(funcea, real_name)
            log("Function %s renamed to %s." % (origin_name, real_name))


if __name__ == '__main__':
    start()
    
    
    