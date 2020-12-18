Refer to "instruction set notes" for a breakdown of what most instructions do.

Opcode syntax is x86-like. Data in MOV moves from the right-operand to the left-operand

## Missing instructions:
* 0x93 - 0x97 Conditional jumps (when flag is not set)
* 0x9B - 0x9F Conditional jumps (when flag is set)
* 0xA0 - 0xAF Not used in H2100
* 0xB0 - 0xB7 Not used in H2100
* 0xB8 Probably a trap to debugger. Unable to test.
* 0xBB Not used in H2100
* 0xBD - 0xBE Not used in H2100

## Missing documentation
* Flag interactions for all instructions
* Why SUBC uses the inverse of the carry flag - seems different to the way that 8051 does the carry flag
