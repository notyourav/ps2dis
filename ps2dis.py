# For configuration

OBJDUMP = "sce/ee/gcc/bin/ee-objdump"
ENTRY_OFF = "0x100010"

'''



'''

from argparse import ArgumentParser
import os, subprocess, sys

USES_LABEL = [ "b", "bc1f", "bc1fl", "bc1t", "bc1tl", "beq", "beql", "beqz", "beqzl", "bgez", "bgezal", "bgezall", "bgezl", "bgtz", "bgtzl", "blez", "blezl", "bltz", "bltzal", "bltzall", "bltzl", "bne", "bnel", "bnez", "bnezl", "j", "jal" ]
#USES_DATA = ["sw", "lw"] # we need extra checks to make sure these refer to offsets
REGISTERS = [ "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "s8", "ra" ]

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

def run_objdump() -> str:
    return subprocess.check_output([OBJDUMP, "-dz", "--start-address=" + ENTRY_OFF, args.input], universal_newlines=True)

def process_objdump_line(line: str) -> Instruction:
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
    result = Instruction(offset, bytes, opcode, operands)
    if len == 4:
        result.isComplete = True
    return result

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
                op = "($%s)" % tmp
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

'''

Program

'''

parser = ArgumentParser()
parser.add_argument("input", help="Input file.")
parser.add_argument("output", help="Output file.")
args = parser.parse_args()

# Run objdump and parse lines
disasm = run_objdump().splitlines()[6:] # remove heading
instructions = []
for line in disasm:
    instructions.append(process_objdump_line(line))

# First iteration: find all addr references
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

print(".text")
print(".align 2")
print(".set noat")
#print(".set noreorder")
print(".include \"macro.inc\"")
print()
print()
print(".ent _start")
print(".global _start")
print("_start:")

# Second iteration: disassemble
for instruction in instructions:
    if instruction.offset in ref_addrs:
        if ref_addrs[instruction.offset]:
            print("") # newline between subs
        print(generate_label(instruction.offset) + ":")

    if instruction.operands == None:
        fmt = instruction.opcode # dont bother with operands, if it has none
    else:
        print("\t" + instruction.opcode + "\t" + parse_operands(instruction))

# with open(args.input, "rb") as elffile:
#     filecontent = bytearray(elffile.read())
