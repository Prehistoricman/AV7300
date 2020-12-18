Developed with Lua 5.1.5. Converts a properly formatted assembly file (custom syntax, sorry) into a hex file.

The output file only contains code, so you can't specify the value of variables.

## Usage
From the command line: ```lua assembler.lua <input_file_name>```

The output file is not the full ROM of the chip. It has a base address and length that have to be configured by editing assembler.lua. The purpose of this is to make the creation of patches and hacks for existing ROMs easier.

## Syntax
### Sections
You can mark a data section (for declaring variables) by using ```.data```

You can mark a code section by using ```.code```

### Labels
Declare a label by specifying a name, optionally an address, followed by a colon. The first letter of a name must not be a number. If no address is specified, the previous address plus 1 is used. Specify an address by writing ```= #<hex address here>```.

### Comments
Make a line comment using the semicolon.

### Instructions
* mov reg, [#addr]
* mov [#addr], reg
* mov reg, label
* mov label, reg
* mov reg, #imm
* mov R0, reg
* jmp label
* jmp #addr
* je label
* jne label
* jz label
* jnz label
* jl label
* jge label
* call label
* ret
* inc reg
* or
* and (only R0 = R0 and R1)
* xor (only R0 = R0 xor R1)
* clr (only R0)
* push reg
* pop reg
* lshift reg
* rshift reg
* cmp R0, reg
* inc16
* db #imm
