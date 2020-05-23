from capstone import *

# code = b'\xzz\x48\x8b\x01'
template_code = b'\x48\x8b\x01'
md = Cs(CS_ARCH_X86, CS_MODE_64)

filter = ()

f = open("asm_out", "w")
for x in range(0x00,0xff):
    gen = bytes([x]) + template_code
    tmp = "-----------------\n"
    tmp += "XX => %s\n" %str(hex(x))
    for i in md.disasm(gen, 0x1):
        if i.mnemonic not in filter:
            tmp += "0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str)
    tmp += "-----------------\n"
    print(tmp)
    f.write(tmp)