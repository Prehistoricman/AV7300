#----------------------------------------------------------------------
# Processor module template script
# (c) Hex-Rays
import sys
import idc
import idaapi
import idautils
from idc import *
from idaapi import *
import ida_ida

import logging
logger = logging.getLogger(__name__)
logging.basicConfig(filename = "disasm.log", level = logging.ERROR)

# define RAM starting at 18000h of size 100h
# define ROM starting at 0 of size 12100h
# The extra 100 is for the first page of data memory

#integer to hex
#width can be used to set the width of the result
def hex(int, width = None):
    if (width == None):
        return "0x%X" % int
    else:
        return ("0x%0." + str(width) + "X") % int

# ----------------------------------------------------------------------
class AV7300_processor(idaapi.processor_t):
    
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 7300
    
    # Processor features
    flag = PR_DEFSEG32 | PRN_HEX | PR_RNAMESOK | PR_CNDINSNS | PR_USE32
    
    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8
    
    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8
    
    #To size set (in bytes, hopefully) of dt_tbyte
    tbyte_size = 2
    
    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['AV7300']
    
    # long processor names
    # No restriction on name lengthes.
    plnames = ['Avnera AV7300']
    
    assembler = {
        "header": [".???"],
        "flag": AS_NCHRE | ASH_HEXF0 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF0 | 0,
        "uflag": 0,
        "name": "AV7300 assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": "'",
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_dword": ".dword",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }
    
    # register names
    reg_names = regNames = [
        "SP", #Required for IDA
        "CS",
        "DS",
        
        "R0",
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
        "R7",
        
        "C", # Carry flag
        "Z", # Zero flag
        "N", # Negative flag
        "R", # Register set flag
        "I", # Interrupt enable flag
        "?", # unknown flag
        "unkn" #placeholder for unknown register
    ]
    
    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    reg_first_sreg = 1 # index of CS
    reg_last_sreg = 2 # index of DS
    
    # size of a segment register in bytes
    segreg_size = 0
    
    # You should define 2 virtual segment registers for CS and DS.
    # number of CS/DS registers
    reg_code_sreg = 1
    reg_data_sreg = 2
    
    '''
    CF_STOP = 0x00001 #  Instruction doesn't pass execution to the next instruction 
    CF_CALL = 0x00002 #  CALL instruction (should make a procedure here) 
    
    CF_CHG1 = 0x00004 #  The instruction modifies the first operand 
    CF_CHG2 = 0x00008 #  The instruction modifies the second operand 
    CF_CHG3 = 0x00010 #  The instruction modifies the third operand 
    CF_CHG4 = 0x00020 #  The instruction modifies 4 operand 
    CF_CHG5 = 0x00040 #  The instruction modifies 5 operand 
    CF_CHG6 = 0x00080 #  The instruction modifies 6 operand 
    
    CF_USE1 = 0x00100 #  The instruction uses value of the first operand 
    CF_USE2 = 0x00200 #  The instruction uses value of the second operand 
    CF_USE3 = 0x00400 #  The instruction uses value of the third operand 
    CF_USE4 = 0x00800 #  The instruction uses value of the 4 operand 
    CF_USE5 = 0x01000 #  The instruction uses value of the 5 operand 
    CF_USE6 = 0x02000 #  The instruction uses value of the 6 operand
    
    CF_JUMP = 0x04000 #  The instruction passes execution using indirect jump or call (thus needs additional analysis) 
    CF_SHFT = 0x08000 #  Bit-shift instruction (shl,shr...) 
    CF_HLL  = 0x10000 #  Instruction may be present in a high level language function. 
    '''
    
    # Array of instructions
    instruc = [
        {'name': 'NOP',    'feature': 0,                 'cmt': "No operation"},
        {'name': 'INC',    'feature': CF_USE1,           'cmt': "Increment"},
        {'name': 'INC16',  'feature': CF_USE1,           'cmt': "16-bit increment"},
        {'name': 'ADD',    'feature': CF_USE1,           'cmt': "Add registers"},
        {'name': 'ADDC',   'feature': CF_USE1,           'cmt': "Add registers with carry"},
        {'name': 'SUBC',   'feature': CF_USE1,           'cmt': "Subtract registers with carry"},
        {'name': 'OR',     'feature': CF_USE1,           'cmt': "Bitwise OR"},
        {'name': 'AND',    'feature': CF_USE1,           'cmt': "Bitwise AND"},
        {'name': 'CLR',    'feature': CF_USE1,           'cmt': "Clear"},
        {'name': 'SET',    'feature': CF_USE1,           'cmt': "Bit set"},
        {'name': 'XOR',    'feature': CF_USE1,           'cmt': "Bitwise XOR"},
        {'name': 'DEC',    'feature': CF_USE1,           'cmt': "Decrement"},
        {'name': 'LSHIFT', 'feature': CF_USE1,           'cmt': "Left shift by 1"},
        {'name': 'RSHIFT', 'feature': CF_USE1,           'cmt': "Right shift by 1 (logical)"},
        
        {'name': 'CMP',    'feature': 0,                 'cmt': "Compare. Do R0 - R1 and set flags"},
        {'name': 'PUSH',   'feature': CF_USE1,           'cmt': "Push register to stack"},
        {'name': 'POP',    'feature': CF_USE1,           'cmt': "Pop register from stack"},
        
        {'name': 'JNZ',    'feature': CF_JUMP,           'cmt': "Jump if not zero"},
        {'name': 'JNC',    'feature': CF_JUMP,           'cmt': "Jump if not carry"},
        {'name': 'JNN',    'feature': CF_JUMP,           'cmt': "Jump if not negative"},
        {'name': 'JNI',    'feature': CF_JUMP,           'cmt': "Jump if interrupts disabled"},
        {'name': 'JZ',     'feature': CF_JUMP,           'cmt': "Jump if zero"},
        {'name': 'JC',     'feature': CF_JUMP,           'cmt': "Jump if carry"},
        {'name': 'JN',     'feature': CF_JUMP,           'cmt': "Jump if negative"},
        {'name': 'JI',     'feature': CF_JUMP,           'cmt': "Jump if interrupts enabled"},
        {'name': 'RET',    'feature': CF_STOP,           'cmt': "Return"},
        {'name': 'RETI',   'feature': CF_STOP,           'cmt': "Return from interrupt"},
        {'name': 'JMP',    'feature': CF_JUMP,           'cmt': "Jump unconditionally"},
        {'name': 'JUNKN',  'feature': CF_JUMP,           'cmt': "Jump of unknown function"},
        {'name': 'CALL',   'feature': CF_CALL,           'cmt': "Call unconditionally"},
        {'name': 'CUNKN',  'feature': CF_CALL,           'cmt': "Call of unknown function"},
        
        {'name': 'MOV',    'feature': CF_USE1 | CF_USE2, 'cmt': "Move data"},
        
        {'name': 'UNKN',   'feature': 0,                 'cmt': "unknown opcode"},
    ]
    
    # icode of the first instruction
    instruc_start = 0
    
    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1
    
    # Icode of return instruction. It is ok to give any of possible return
    # instructions
    # for x in instruc:
        # if x['name'] == 'RET':
            # icode_return = instruc.index(x)
    
    #Called at module initialization.
    def notify_init(self, idp_file):
        logging.info("notify_init")
        ida_ida.cvar.inf.set_wide_high_byte_first(False)  #little endian
        ida_ida.cvar.inf.set_be(False)  #AWFUL documentation
        return True
    
    def notify_newfile(self, filename):
        pass
    
    def notify_get_autocmt(self, insn):
        name = insn.get_canon_mnem()
        #Search instruc for this name
        for entry in self.instruc:
            if entry["name"] == name:
                return entry["cmt"]
        return "No comment for this instruction"
    
    #gets an instruction table index from instruc by name
    def get_instruction(self, name):
        for x in self.instruc:
            if x['name'] == name:
                return self.instruc.index(x)
        raise Exception("Could not find instruction %s" % name)
    
    #returns name if name exists in regNames
    def get_register(self, name):
        for x in self.regNames:
            if x == name:
                return self.regNames.index(x)
        raise Exception("Could not find register %s" % name)
    
    repeats = {}
    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure (insn_t).
        If zero is returned, the kernel will delete the instruction.
        """
        logging.info("notify_emu")
        
        feature = insn.get_canon_feature()
        mnemonic = insn.get_canon_mnem()
        
        #is it an unconditional jump?
        uncond_jmp = False
        if insn.itype == self.get_instruction('JMP'):
            uncond_jmp = True
        
        #is it a jump?
        if feature & CF_JUMP > 0: #If the instruction has the CF_JUMP flag
            insn.add_cref(insn[0].addr, 0, fl_JN)
        
        #is it a call?
        if feature & CF_CALL > 0: #If the instruction has the CF_CALL flag
            insn.add_cref(insn[0].addr, 0, fl_CN)
        
        #Does the processor go to the next instruction?
        flow = (feature & CF_STOP == 0) and not uncond_jmp
        if flow:
            insn.add_cref(insn.ea + insn.size, 0, fl_F)
        
        #Add data reference
        #TODO read/write flag
        for i in range(6):
            op = insn[i]
            if op.type == o_mem:
                #If the memory is read, specval will be 1
                rw = dr_R if op.specval == 1 else dr_W
                
                insn.add_dref(op.addr, insn.ea, rw)
        
        return 1
        
    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Invoked when out_one_operand is called
        Returns: 1-ok, 0-operand is hidden.
        """
        logging.info("notify_out_operand")
        
        optype = op.type
        
        if optype == o_reg:
            ctx.out_register(self.regNames[op.reg])
            
            if op.specflag1:
                ctx.out_symbol(".")
                ctx.out_long(op.specval, 10)
            
        elif optype == o_imm:
            ctx.out_symbol("#")
            ctx.out_value(op, OOFW_IMM)
            logging.debug("notify_out_operand immediate value: " + hex(op.value))
            
        elif optype == o_near:
            op.dtype = dt_word
            ok = ctx.out_name_expr(op, op.addr, BADADDR)
            logging.debug("notify_out_operand op addr: " + hex(op.addr))
            if not ok:
                #When op.addr is either indirect or references outside of the address space
                #ctx.out_tagon(COLOR_ERROR)
                ctx.out_long(op.addr, 16)
                #ctx.out_tagoff(COLOR_ERROR)
        
        elif optype == o_mem:
            #ctx.out_addr_tag(op.addr) #Does nothing??
            op.dtype = dt_word
            
            ctx.out_symbol("[")
            ctx.out_value(op, OOF_ADDR | OOFW_IMM)
            ctx.out_symbol("]")
            
        elif optype == o_phrase or optype == o_displ:
            # For register indirect indexing
            ctx.out_symbol("[")
            ctx.out_register("R" + str(op.specval + 1))
            ctx.out_register("R" + str(op.specval))
            
            if optype == o_displ:
                ctx.out_symbol("+")
                op.dtype = dt_byte
                ctx.out_value(op, OOF_ADDR | OOFW_IMM)
            
            ctx.out_symbol("]")
        
        else:
            logging.error("notify_out_operand op type " + str(optype) + " failed in outop")
            return False
        
        return True
    
    def notify_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        logging.info("notify_out_insn for " + self.instruc[ctx.insn.itype]["name"] + " at " + hex(ctx.insn.ea))
        
        ctx.out_mnemonic()
        insn = ctx.insn
        
        # output first operand
        if insn[0].type != o_void:
            ctx.out_one_operand(0)
        
        # output 1st instruction operands
        for i in xrange(1, 4):
            if insn[i].type == o_void:
                break
            ctx.out_symbol(",")
            ctx.out_char(" ")
            ctx.out_one_operand(i)
        
        ctx.flush_outbuf()
    
    
    
    
    
    
    
    def ana_addregs(self, regs):
        logging.info("ana_addregs")
        #For instructions that operate on R0
        i = 0
        for reg in regs:
            self.insn[i].type = o_reg
            self.insn[i].reg = self.get_register(reg)
            i = i + 1
    
    def ana_two_reg(self, mnemonic, base, swap = False):
        logging.info("ana_two_reg")
        self.insn.itype = self.get_instruction(mnemonic)
        
        r0 = 0
        r1 = 1
        if swap:
            r0 = 1
            r1 = 0
        
        self.insn[r0].type = o_reg
        self.insn[r0].reg = self.get_register("R0")
        
        #Get the register being read
        reg_name = "R" + str(self.opcode - base)
        
        self.insn[r1].type = o_reg
        self.insn[r1].reg = self.get_register(reg_name)
    
    def ana_single_reg(self, mnemonic, base):
        logging.info("ana_single_reg")
        self.insn.itype = self.get_instruction(mnemonic)
        
        #Get the register being read
        reg_name = "R" + str(self.opcode - base)
        
        self.insn[0].type = o_reg
        self.insn[0].reg = self.get_register(reg_name)
    
    def ana_bittest(self):
        logging.info("ana_bittest")
        # MOV Z, R0.2
        self.insn.itype = self.get_instruction("MOV")
        
        self.insn[0].type = o_reg
        self.insn[0].reg = self.get_register("Z")
        
        self.insn[1].type = o_reg
        self.insn[1].reg = self.get_register("R0")
        self.insn[1].specflag1 = 1
        self.insn[1].specval = self.opcode - 0x60
    
    def ana_rjmp(self):
        logging.info("ana_rjmp")
        offset = self.insn.get_next_byte()
        
        #Convert offset from 2's complement to signed
        if offset >= 0x80:
            offset = -(0x100 - offset)
        
        self.insn[0].type = o_near
        # + 2 for the size of this instruction itself
        self.insn[0].addr = self.insn.ea + 2 + offset
        
        instr_name = ""
        if self.opcode == 0x90:
            instr_name = "JNZ"
        elif self.opcode == 0x91:
            instr_name = "JNC"
        elif self.opcode == 0x92:
            instr_name = "JNN"
        elif self.opcode == 0x95:
            instr_name = "JNI"
            
        elif self.opcode == 0x98:
            instr_name = "JZ"
        elif self.opcode == 0x99:
            instr_name = "JC"
        elif self.opcode == 0x9A:
            instr_name = "JN"
        elif self.opcode == 0x9D:
            instr_name = "JI"
            
        else:
            instr_name = "JUNKN"
        
        self.insn.itype = self.get_instruction(instr_name)
    
    def ana_ajmp(self):
        logging.info("ana_ajmp")
        LSb = self.insn.get_next_byte()
        MSb = self.insn.get_next_byte()
        
        addr = (MSb << 8) + LSb
        
        self.insn[0].type = o_near
        self.insn[0].addr = int(addr)
    
    def ana_write(self):
        logging.info("ana_write")
        self.insn.itype = self.get_instruction("MOV")
        LSb = self.insn.get_next_byte()
        MSb = self.insn.get_next_byte()
        
        addr = (MSb << 8) + LSb
        self.insn[0].type = o_mem
        self.insn[0].addr = addr
        self.insn[0].specval = 0 #Write
        logging.info("ana_write address is " + str(hex(addr)))
        
        #Get the register being read
        reg_name = "R" + str(self.opcode - 0xC8)
        
        self.insn[1].type = o_reg
        self.insn[1].reg = self.get_register(reg_name)
    
    def ana_loadimm(self):
        logging.info("ana_loadimm")
        self.insn.itype = self.get_instruction("MOV")
        
        #Get the register being read
        reg_name = "R" + str(self.opcode - 0xE0)
        
        self.insn[0].type = o_reg
        self.insn[0].reg = self.get_register(reg_name)
        
        imm = self.insn.get_next_byte()
        self.insn[1].type = o_imm
        self.insn[1].value = imm
    
    def ana_loadaddr(self):
        logging.info("ana_loadaddr")
        self.insn.itype = self.get_instruction("MOV")
        
        #Get the register being read
        reg_name = "R" + str(self.opcode - 0xE8)
        
        self.insn[0].type = o_reg
        self.insn[0].reg = self.get_register(reg_name)
        
        LSb = self.insn.get_next_byte()
        MSb = self.insn.get_next_byte()
        
        addr = (MSb << 8) + LSb
        self.insn[1].type = o_mem
        self.insn[1].addr = addr
        self.insn[1].specval = 1 #Read
    
    def ana_indirect(self):
        logging.info("ana_indirect")
        self.insn.itype = self.get_instruction("MOV")
        
        base = self.opcode & 0xF8
        
        #Two instruction variants: with and without offset
        offset = (self.opcode & 0x08) > 0
        
        r0 = 0
        r1 = 1
        if self.opcode <= 0xDF:
            r0 = 1
            r1 = 0
        
        self.insn[r0].type = o_reg
        self.insn[r0].reg = self.get_register("R0")
        
        if offset:
            self.insn[r1].type = o_displ
            self.insn[r1].addr = self.insn.get_next_byte()
        else:
            self.insn[r1].type = o_phrase
        
        self.insn[r1].specval = self.opcode - base
    
    def ana_flagmanip(self, mnemonic):
        logging.info("ana_flagmanip")
        self.insn.itype = self.get_instruction(mnemonic)
        
        flag = self.opcode & 0x07
        flags = ["Z", "C", "N", "R", "?", "I", "?", "?"]
        
        self.ana_addregs([flags[flag]])
    
    def notify_ana(self, insn):
        logging.info("================= notify_ana =================")
        
        opcode = insn.get_next_byte()
        self.opcode = opcode
        logging.info("notify_ana opcode: " + hex(opcode))
        
        self.insn = insn
        insn.size = 1 #This value will be incremented by get_next_byte
        
        if opcode >= 0x00 and opcode <= 0x07:
            self.ana_single_reg("INC", 0x00)
        elif opcode >= 0x08 and opcode <= 0x0F:
            self.ana_two_reg("ADDC", 0x08)
        elif opcode == 0x10:
            insn.itype = self.get_instruction("NOP")
        elif opcode >= 0x11 and opcode <= 0x17:
            self.ana_two_reg("MOV", 0x10)
        elif opcode >= 0x18 and opcode <= 0x1F:
            self.ana_two_reg("OR", 0x18)
        elif opcode >= 0x21 and opcode <= 0x27:
            self.ana_two_reg("AND", 0x20)
        elif opcode == 0x28:
            insn.itype = self.get_instruction("CLR")
            self.ana_addregs(["R0"])
        elif opcode >= 0x29 and opcode <= 0x2F:
            self.ana_two_reg("XOR", 0x28)
        elif opcode >= 0x30 and opcode <= 0x37:
            self.ana_single_reg("LSHIFT", 0x30)
        elif opcode >= 0x38 and opcode <= 0x3F:
            self.ana_single_reg("RSHIFT", 0x38)
        elif opcode >= 0x40 and opcode <= 0x47:
            self.ana_single_reg("DEC", 0x40)
        elif opcode >= 0x48 and opcode <= 0x4F:
            self.ana_two_reg("SUBC", 0x48)
        elif opcode >= 0x50 and opcode <= 0x57:
            self.ana_two_reg("ADD", 0x50)
        elif opcode >= 0x58 and opcode <= 0x5F:
            self.ana_flagmanip("SET")
        elif opcode >= 0x60 and opcode <= 0x67:
            self.ana_bittest()
        elif opcode >= 0x68 and opcode <= 0x6F:
            self.ana_flagmanip("CLR")
        elif opcode >= 0x70 and opcode <= 0x77:
            self.ana_two_reg("MOV", 0x70, swap = True)
        elif opcode >= 0x78 and opcode <= 0x7F:
            self.ana_two_reg("CMP", 0x78)
        elif opcode >= 0x80 and opcode <= 0x8F:
            if opcode <= 0x87:
                self.ana_single_reg("PUSH", 0x80)
            else:
                self.ana_single_reg("POP", 0x88)
        elif opcode >= 0x90 and opcode <= 0x9F:
            self.ana_rjmp()
        elif opcode == 0xB9:
            insn.itype = self.get_instruction("RET")
        elif opcode == 0xBA:
            insn.itype = self.get_instruction("RETI")
        elif opcode == 0xBC:
            self.ana_ajmp()
            insn.itype = self.get_instruction("JMP")
        elif opcode == 0xBF:
            self.ana_ajmp()
            insn.itype = self.get_instruction("CALL")
        elif opcode >= 0xC0 and opcode <= 0xC7:
            insn.itype = self.get_instruction("INC16")
            if opcode == 0xC0:
                self.ana_addregs(["R0", "R1"])
            elif opcode == 0xC2:
                self.ana_addregs(["R2", "R3"])
            elif opcode == 0xC4:
                self.ana_addregs(["R4", "R5"])
            elif opcode == 0xC6:
                self.ana_addregs(["R6", "R7"])
        elif opcode >= 0xC8 and opcode <= 0xCF:
            self.ana_write()
        elif opcode >= 0xD0 and opcode <= 0xDF:
            self.ana_indirect()
        elif opcode >= 0xE0 and opcode <= 0xE7:
            self.ana_loadimm()
        elif opcode >= 0xE8 and opcode <= 0xEF:
            self.ana_loadaddr()
        elif opcode >= 0xF0 and opcode <= 0xFF:
            self.ana_indirect()
        else:
            logging.info("unknown instruction "  + hex(opcode))
            insn.size = 0
            return 0
            #insn.itype = self.get_instruction("UNKN")
            #insn[0].type = o_imm
            #insn[0].value = opcode
                
        # Return decoded instruction size or zero
        return insn.size
    
    
    
    
    
    def __init__(self):
        idaapi.processor_t.__init__(self)
        logging.info("module instantiated")
  
# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    logging.info("PROCESSOR_ENTRY")
    return AV7300_processor()
