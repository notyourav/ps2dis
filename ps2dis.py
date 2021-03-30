# For configuration

OBJDUMP = "sce/ee/gcc/bin/ee-objdump"
ENTRY_OFF = "0x100010"  # virtual addr

'''



'''

from argparse import ArgumentParser
import os, subprocess, sys
from typing import List

USES_LABEL = [ "b", "bc1f", "bc1fl", "bc1t", "bc1tl", "beq", "beql", "beqz", "beqzl", "bgez", "bgezal", "bgezall", "bgezl", "bgtz", "bgtzl", "blez", "blezl", "bltz", "bltzal", "bltzall", "bltzl", "bne", "bnel", "bnez", "bnezl", "j", "jal" ]
#USES_DATA = ["sw", "lw"] # we need extra checks to make sure these refer to offsets
REGISTERS = [ "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "s8", "ra" ]

class Section:
    name: str
    size: str
    vaddr: str
    offset: str
    align: str
    flags: str

    def __init__(self, name, size, vaddr, offset, align, flags) -> None:
        self.name = name
        self.size = size
        self.vaddr = vaddr
        self.offset = offset
        self.align = align
        self.flags = flags

class Instruction:
    offset: str
    bytes: str
    opcode: str
    operands: str
    isComplete: bool # has all of the above?

    def __init__(self, offset, bytes, opcode, operands) -> None:
        self.offset = offset
        self.bytes = bytes
        self.opcode = opcode
        self.operands = operands

def fail(msg: str):
    print(msg, file=sys.stderr)
    sys.exit(1)

def generate_label(offset: str):
    if int(offset, 16) < int(ENTRY_OFF, 16):
        return offset
    if offset not in ref_addrs:
        fail("Unknown referenced: " + offset)
    if ref_addrs[offset]:
        return "sub_" + offset.upper().zfill(8)
    else:
        return "lbl_" + offset.upper().zfill(8)

def run_objdump(options) -> str:
    return subprocess.check_output([OBJDUMP] + options, universal_newlines=True)

def get_instructions():
    result = []
    for line in disasm:
        offset, bytes, opcode, operands = None, None, None, None
        col = line.split("\t")
        if len(col) >= 1:
            offset = col[0][:-1].strip()
        if len(col) >= 2:
            bytes = col[1]
        if len(col) >= 3:
            opcode = col[2]
        if len(col) >= 4:
            operands = col[3]
        instr = Instruction(offset, bytes, opcode, operands)
        if len == 4:
            instr.isComplete = True
        result.append(instr)
    return result

def find_code_labels():
    ref_addrs = {"x" : False} # TRUE = sub, FALSE = lbl
    for instruction in instructions:
        if instruction.opcode in USES_LABEL:
            addr, isSub = get_ref_from_instr(instruction)
            if int(addr, 16) < int(ENTRY_OFF, 16): # Ignore sub_00000000
                continue
            if addr in ref_addrs:
                ref_addrs[addr] = ref_addrs[addr] or isSub # consider it a sub if ANY reference is a jal
            else:
                ref_addrs[addr] = isSub
    return ref_addrs

def parse_operands(instruction: Instruction) -> str:
    if instruction.opcode in USES_LABEL:
        # add the label
        ops = parse_ref_in_instr(instruction)
    else:
        ops = instruction.operands

    result = []
    for op in ops.split(","):
        # op => $op
        if op in REGISTERS:
            op = "$" + op
        else:
            tmp = op.split("(").pop().strip(")")
            # (op) => ($op)
            if tmp in REGISTERS:
                op = op.split("(")[0] + "($%s)" % tmp
        result.append(op)

    # spacing between operands
    return ", ".join(result)

def parse_ref_in_instr(instruction: Instruction) -> str:
    s = instruction.operands.split(",")
    addr = generate_label(s.pop().replace("0x", ""))
    if len(s) != 0:
        return ",".join(s) + "," + addr
    return addr

def get_ref_from_instr(instruction: Instruction):
    ref_is_sub = instruction.opcode in [ "jal" ]
    addr = instruction.operands.split(",").pop().replace("0x", "")
    return addr, ref_is_sub

data_refs = {}
def check_instr_for_data(instruction: Instruction):
    #if instruction.opcode == 
    pass

def get_sections():
    dmp = run_objdump(["-h", args.input]).splitlines()[5:]
    # get section information from objdump. Note how vaddr and laddr are the same.
    # Idx Name          Size      VMA       LMA       File off  Algn
    #   0 .text         0002eaec  00100000  00100000  00001000  2**6
    #                   CONTENTS, ALLOC, LOAD, READONLY, CODE
    sects = {}
    i = 0
    for line in dmp[::2]:
        split = line.split()
        sect_name = split[1]
        size = split[2]
        vaddr =  split[3]
        offset = split[5]
        align = split[6]
        flags = ""
        modlist = dmp[i + 1]
        if modlist.find("ALLOC") != -1:
            flags += "a"
        # if modlist.find("LOAD") != -1:
        if modlist.find("READONLY") == -1:
            flags += "w"
        if modlist.find("CODE") != -1:
            flags += "x"
        sects[sect_name] = Section(sect_name, size, vaddr, offset, align, flags)
        i += 2
    return sects

def disassemble():
    for instruction in instructions:
        if "0x" + instruction.offset == ENTRY_OFF:
            print(".global _start")
            print("_start:")
        if instruction.offset in ref_addrs:
            if ref_addrs[instruction.offset]:
                print("") # newline between subs
            print(generate_label(instruction.offset) + ":")

        if instruction.opcode.find("0x") != -1: # todo: handle data embedded in text section
            pass
        if instruction.operands == None: # dont bother with operands, if it has none
            print("\t" + instruction.opcode)
        else:
            print("\t" + instruction.opcode + "\t" + parse_operands(instruction))

'''

Program

'''

parser = ArgumentParser()
parser.add_argument("input", help="Input file.")
#parser.add_argument("output", help="Output file.")
args = parser.parse_args()

with open(args.input, "rb") as elffile:
    filecontent = bytearray(elffile.read())

# Run objdump and parse lines
disasm = run_objdump(["-dz", args.input]).splitlines()[6:] # remove heading
instructions = get_instructions()
sections = get_sections()
ref_addrs = find_code_labels()

print(".set noat")
print(".set noreorder")
#print(".set noreorder")
print(".include \"macro.inc\"")
print(".ent _start")
print("\n")
# this is really ugly but is needed in order to use symbolic register names.
print("#define zero 0\n#define at 1\n#define v0 2\n#define v1 3\n#define a0 4\n#define a1 5\n#define a2 6\n#define a3 7\n#define t0 8\n#define t1 9\n#define t2 10\n#define t3 11\n#define t4 12\n#define t5 13\n#define t6 14\n#define t7 15\n#define s0 16\n#define s1 17\n#define s2 18\n#define s3 19\n#define s4 20\n#define s5 21\n#define s6 22\n#define s7 23\n#define t8 24\n#define t9 25\n#define k0 26\n#define k1 27\n#define gp 28\n#define sp 29\n#define fp 30\n#define s8 30\n#define ra 31")
print("\n")

for secname in sections:
    sect = sections[secname]
    print(".section %s, \"%s\"" % (sect.name, sect.flags))
    print(".align %s" % sect.align.split("*").pop())
    if secname in [".data", ".ctors", ".dtors", ".eh_frame", ".rodata", ".lit4", ".sdata", ".reginfo"]: # need incbin
        print(".incbin \"%s\", %s, %s" % (args.input, "0x" + sect.offset.upper(), "0x" + sect.size.upper()))
    elif secname in [".text_nop",".data_nop",".sbss", ".bss", ".mdebug.eabi64"]:
        print(".skip %s" % "0x" + sect.size)
    elif secname == ".text":
        disassemble()

    print("\n")

#print(".end")

# incbins = []
# for key in data_refs:
#     # assume sorted

#     pass