# AV7300
The Avnera AV7300 series is a series of wireless audio chipsets used in some headsets. For example, the Corsair Vengeance HS2100 and Turtle Beach PX3.
The AV7320 member of the family is specific to the base station and most likely doesn't have a microphone input or speaker amplifier.

## Instruction set
The instructions have been figured out purely from reverse engineering, and thus some are missing. Most of the missing ones are due to not knowing the meaning of all the processor flags. See "instruction set notes" for more info.

## Disassembler
An IDA disassembler module can be found in the Disassembler directory. Copy the python file to your IDA 'procs' directory to install. Developed on IDA 7.2.

## Assembler
I made a quick and dirty assembler for this chip in Lua. Not all the discovered instructions are available here, but you can specify raw bytes to get around that. See the example \*.s files and the readme.

