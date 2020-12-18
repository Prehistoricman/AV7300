args = {...}
------ User vars ------
Assembly_file_name = args[1] or "assembly.s"
ROM_output_file_name = "ROM.hex"
ROMBaseAddr = 0xD599 --The address of the first byte of the output file
ROMLength = 0x1FF --The length of the output file in bytes

------ Internal vars ------
CurrMode = "T" --T for text/code, D for data
ROMtext = "" --String builder for ROM
CurrROMAddr = ROMBaseAddr
ROM = {} --Table of values
CurrRAMAddr = 0
RAM = {} --Table of values

--Table of labels, each of which is a table of the address and type
Labels = {}

--Regex to match a data or text label
LABEL_REGEX = "[a-zA-Z_][a-zA-Z_0-9]*"
REG_REGEX = "[rR][0-9]"
REG_REGEX_SELECT = "[rR]([0-9])"
ADDR_REGEX = "#%x+"
ADDR_REGEX_SELECT = "#(%x+)"

------ Program ------

--Instructions:
--[[
mov reg, [#addr]
mov [#addr], reg
mov reg, label
mov label, reg
mov reg, #imm
mov R0, reg
jmp label
jmp #addr
je label
jne label
jz label
jnz label
jl label
jge label
call label
ret
inc reg
or
and (only R0 = R0 and R1)
xor (only R0 = R0 xor R1)
clr (only R0)
push reg
pop reg
lshift reg
rshift reg
cmp R0, reg
inc16
db #imm
]]

--Extracts the mneemonic and returns it, plus the rest of the line
function GetMnemonic(line)
	local mnemonic = line:match("^%s*([a-zA-Z_0-9]+)")
	
	--If nothing was found, exit
	if not mnemonic then
		return nil
	end
	
	--Get the end position to cut the string
	local mnem_start, mnem_end = line:find("^%s*[a-zA-Z_0-9]+")
	
	return mnemonic:lower(), line:sub(mnem_end + 1)
end

--Write a label's address to ROM
--Will input the label and type if the label is not yet resolved
function UseCodeLabel(label, labelType, addr)
	--Accessing an already defined label?
	if Labels[label] and Labels[label][1] then
		--Is it a text label?
		if Labels[label][2] ~= labelType and not (Labels[label][2] == "T" and labelType == "R") then
			error("Reference to wrong label type (text or data): " .. label)
		end
		
		--Fill in address
		if labelType == "R" then
			local dest = Labels[label][1]
			local dist = Labels[label][1] - (addr + 1) -- +1 because relative jumps are 2 bytes long
			if dist > 127 or dist < -180 then
				error("Relative jump out of range! desination label: " .. label)
			end
			
			--2's complement conversion
			ROM[addr] = dist < 0 and dist + 0x100 or dist
		else
			ROM[addr] = Labels[label][1] % 0x100
			ROM[addr+1] = math.floor(Labels[label][1] / 256)
		end
	else
		ROM[addr] = {label, labelType} --Needs to be filled in with an address later
	end
end

--Processes the given text and looks for a label
function ProcessLabel(line)
	--Is this line a label?
	if not (line:find("^%s*" .. LABEL_REGEX .. "%s*=%s*" .. ADDR_REGEX .. "%s*:") or
			line:find("^%s*" .. LABEL_REGEX .. "%s*:")) then
		return false
	end
	
	local beginning_start, beginning_end = line:find("^%s*" .. LABEL_REGEX)
	--Check if there is a match
	if not beginning_start then
		--print("Not a label: ", line)
		return false
	end
	
	local label = line:match("^%s*(" .. LABEL_REGEX .. ")")
	if not label then
		print("How did this happen?", line)
	end
	
	--Check to make sure this label isn't used already
	if Labels[label] and Labels[label][1] then
		--Is this a default label?
		if Labels[label][3] then
			--Allow one use
			Labels[label][3] = nil
		else
			print("Label already defined:", label)
			return false
		end
	end
	
	--Get the text after the label
	local end_str = line:sub(beginning_end+1)
	
	--Regex to match a potential address
	local addr = end_str:match("^%s*=%s*" .. ADDR_REGEX_SELECT .. "%s*:")
	if addr then
		--Convert address from hex
		addr = tonumber(addr, 16)
		
		--Trim address off of end_str
		local mid_start, mid_end = end_str:find("^%s*=%s*" .. ADDR_REGEX .. "%s*:")
		end_str = end_str:sub(mid_end)
	else
		--No address was given, use current
		--str should match ^%s*:
		if not end_str:match("^%s*:") then
			print("Syntax error near end of label", end_str)
			return false
		end
		
		if CurrMode == "T" then
			if Labels[label] and Labels[label][1] then
				addr = Labels[label][1]
			else
				addr = CurrROMAddr
			end
		else
			addr = CurrRAMAddr
		end
	end
	
	
	if CurrMode == "T" then
		--This is a code label
		CurrROMAddr = addr
		Labels[label] = {addr, "T"}
	else
		--This is a data label
		CurrRAMAddr = addr + 1
		
		--Ripped out code populating the RAM table
		
		RAM[addr] = 0 --value
		Labels[label] = {addr, "D"}
	end
	
	return true
end

--Returns bool success
function ProcessCode(line)
	if ProcessLabel(line) then
		return true
	end
	
	--Now treat it as as instruction
	
	local mnemonic, the_rest = GetMnemonic(line)
	
	--If no instruction, quit
	if not mnemonic then
		--TODO: check for invalid line or comment
		return true
	end
	
	--Do we have an instruction?
	if mnemonic == "mov" then -------------------------- MOV --------------------------
		if the_rest:match("^%s*" .. REG_REGEX .. "%s*,%s*%[%s*" .. ADDR_REGEX .. "%s*%]") then
			--mov reg, [addr]
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT .. "%s*,%s*%[%s*" .. ADDR_REGEX .. "%s*%]"))
			local addr = tonumber(the_rest:match("^%s*" .. REG_REGEX .. "%s*,%s*%[%s*" .. ADDR_REGEX_SELECT .. "%s*%]"), 16)
			
			--choose opcode
			ROM[CurrROMAddr] = 0xE8 + reg
			ROM[CurrROMAddr+1] = addr % 0x100
			ROM[CurrROMAddr+2] = math.floor(addr / 256)
			
			CurrROMAddr = CurrROMAddr + 3
			
			
		elseif the_rest:match("^%s*%[%s*" .. ADDR_REGEX .. "%s*%],%s*" .. REG_REGEX .. "%s*") then
			--mov [addr], reg
			local addr = tonumber(the_rest:match("^%s*%[%s*" .. ADDR_REGEX_SELECT .. "%s*%],%s*" .. REG_REGEX .. "%s*"), 16)
			local reg = tonumber(the_rest:match("^%s*%[%s*" .. ADDR_REGEX .. "%s*%],%s*" .. REG_REGEX_SELECT .. "%s*"))
			
			--choose opcode
			ROM[CurrROMAddr] = 0xC8 + reg
			ROM[CurrROMAddr+1] = addr % 0x100
			ROM[CurrROMAddr+2] = math.floor(addr / 256)
			
			CurrROMAddr = CurrROMAddr + 3
			
		elseif the_rest:match("^%s*R0%s*,%s*" .. REG_REGEX .. "%s*") then
			--mov R0, reg
			local reg = tonumber(the_rest:match("^%s*R0%s*,%s*" .. REG_REGEX_SELECT .. "%s*"))
			
			--choose opcode
			ROM[CurrROMAddr] = 0x10 + reg
			
			CurrROMAddr = CurrROMAddr + 1
			
		elseif the_rest:match("^%s*" .. REG_REGEX .. "%s*,%s*" .. LABEL_REGEX) then
			--mov reg, label
			--should be a data label
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT .. "%s*,%s*" .. LABEL_REGEX .. "%s*"))
			local label = the_rest:match("^%s*" .. REG_REGEX .. "%s*,%s*(" .. LABEL_REGEX .. ")")
			
			
			UseCodeLabel(label, "D", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0xE8 + reg
			
			CurrROMAddr = CurrROMAddr + 3
			
		elseif the_rest:match("^%s*" .. LABEL_REGEX .. "%s*,%s*" .. REG_REGEX .. "%s*") then
			--mov label, reg
			--should be a data label
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")%s*,%s*" .. REG_REGEX .. "%s*")
			local reg = tonumber(the_rest:match("^%s*" .. LABEL_REGEX .. "%s*,%s*" .. REG_REGEX_SELECT .. "%s*"))
			
			
			UseCodeLabel(label, "D", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0xC8 + reg
			
			CurrROMAddr = CurrROMAddr + 3
			
		elseif the_rest:match("^%s*" .. REG_REGEX .. "%s*,%s*" .. ADDR_REGEX .. "%s*") then
			--mov reg, imm
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT .. "%s*,%s*" .. ADDR_REGEX .. "%s*"))
			local imm = tonumber(the_rest:match("^%s*" .. REG_REGEX .. "%s*,%s*" .. ADDR_REGEX_SELECT .. "%s*"), 16)
			
			--choose opcode
			ROM[CurrROMAddr] = 0xE0 + reg
			ROM[CurrROMAddr+1] = imm
			
			CurrROMAddr = CurrROMAddr + 2
			
		else
			print("Bad mov operands:", the_rest)
			return false
		end
	elseif mnemonic == "push" then -------------------------- PUSH --------------------------
		if the_rest:match("^%s*" .. REG_REGEX) then
			--push reg
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT))
			
			--choose opcode
			ROM[CurrROMAddr] = 0x80 + reg
			
			CurrROMAddr = CurrROMAddr + 1
		else
			print("Bad push operands:", the_rest)
			return false
		end
	elseif mnemonic == "pop" then -------------------------- POP --------------------------
		if the_rest:match("^%s*" .. REG_REGEX) then
			--pop reg
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT))
			
			--choose opcode
			ROM[CurrROMAddr] = 0x88 + reg
			
			CurrROMAddr = CurrROMAddr + 1
		else
			print("Bad pop operands:", the_rest)
			return false
		end
	elseif mnemonic == "jmp" then -------------------------- JMP --------------------------
		if the_rest:match("^%s*" .. LABEL_REGEX) then
			--jmp label
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")")
			
			UseCodeLabel(label, "T", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0xBC
			
			CurrROMAddr = CurrROMAddr + 3
		elseif the_rest:match("^%s*" .. ADDR_REGEX) then
			--jmp addr
			local addr = tonumber(the_rest:match("^%s*" .. ADDR_REGEX_SELECT), 16)
			
			--choose opcode
			ROM[CurrROMAddr] = 0xBC
			ROM[CurrROMAddr+1] = addr % 0x100
			ROM[CurrROMAddr+2] = math.floor(addr / 256)
			
			CurrROMAddr = CurrROMAddr + 3
		else
			print("Bad jmp operand:", the_rest)
			return false
		end
	elseif mnemonic == "je" then -------------------------- JE --------------------------
		if the_rest:match("^%s*" .. LABEL_REGEX) then
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")")
			
			UseCodeLabel(label, "R", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0x98
			
			CurrROMAddr = CurrROMAddr + 2
		else
			print("Bad je operand:", the_rest)
			return false
		end
	elseif mnemonic == "jne" then -------------------------- JNE --------------------------
		if the_rest:match("^%s*" .. LABEL_REGEX) then
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")")
			
			UseCodeLabel(label, "R", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0x90
			
			CurrROMAddr = CurrROMAddr + 2
		else
			print("Bad je operand:", the_rest)
			return false
		end
	elseif mnemonic == "jz" then -------------------------- JZ --------------------------
		if the_rest:match("^%s*" .. LABEL_REGEX) then
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")")
			
			UseCodeLabel(label, "R", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0x98
			
			CurrROMAddr = CurrROMAddr + 2
		else
			print("Bad je operand:", the_rest)
			return false
		end
	elseif mnemonic == "jnz" then -------------------------- JNZ --------------------------
		if the_rest:match("^%s*" .. LABEL_REGEX) then
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")")
			
			UseCodeLabel(label, "R", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0x90
			
			CurrROMAddr = CurrROMAddr + 2
		else
			print("Bad je operand:", the_rest)
			return false
		end
	elseif mnemonic == "jc" then -------------------------- JC --------------------------
		if the_rest:match("^%s*" .. LABEL_REGEX) then
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")")
			
			UseCodeLabel(label, "R", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0x99
			
			CurrROMAddr = CurrROMAddr + 2
		else
			print("Bad jl operand:", the_rest)
			return false
		end
	elseif mnemonic == "jgc" then -------------------------- JNC --------------------------
		if the_rest:match("^%s*" .. LABEL_REGEX) then
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")")
			
			UseCodeLabel(label, "R", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0x91
			
			CurrROMAddr = CurrROMAddr + 2
		else
			print("Bad jg operand:", the_rest)
			return false
		end
	elseif mnemonic == "call" then -------------------------- CALL --------------------------
		if the_rest:match("^%s*" .. LABEL_REGEX) then
			local label = the_rest:match("^%s*(" .. LABEL_REGEX .. ")")
			
			UseCodeLabel(label, "T", CurrROMAddr+1)
			
			--choose opcode
			ROM[CurrROMAddr] = 0xBF
			
			CurrROMAddr = CurrROMAddr + 3
		else
			print("Bad call operand:", the_rest)
			return false
		end
	elseif mnemonic == "lshift" then -------------------------- LSHIFT --------------------------
		if the_rest:match("^%s*" .. REG_REGEX) then
			--lshift reg
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT))
			
			--choose opcode
			ROM[CurrROMAddr] = 0x30 + reg
			
			CurrROMAddr = CurrROMAddr + 1
		else
			print("Bad lshift operands:", the_rest)
			return false
		end
	elseif mnemonic == "rshift" then -------------------------- RSHIFT --------------------------
		if the_rest:match("^%s*" .. REG_REGEX) then
			--lshift reg
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT))
			
			--choose opcode
			ROM[CurrROMAddr] = 0x38 + reg
			
			CurrROMAddr = CurrROMAddr + 1
		else
			print("Bad rshift operands:", the_rest)
			return false
		end
	elseif mnemonic == "cmp" then -------------------------- CMP --------------------------
		if the_rest:match("^%s*R0%s*,%s*" .. REG_REGEX) then
			--cmp R0, reg
			local reg = tonumber(the_rest:match("^%s*R0%s*,%s*" .. REG_REGEX_SELECT))
			
			--choose opcode
			ROM[CurrROMAddr] = 0x78 + reg
			
			CurrROMAddr = CurrROMAddr + 1
		else
			print("Bad cmp operands:", the_rest)
			return false
		end
	elseif mnemonic == "inc" then -------------------------- INC --------------------------
		if the_rest:match("^%s*" .. REG_REGEX) then
			--inc reg
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT))
			
			--choose opcode
			ROM[CurrROMAddr] = 0x00 + reg
			
			CurrROMAddr = CurrROMAddr + 1
		else
			print("Bad inc operands:", the_rest)
			return false
		end
	elseif mnemonic == "dec" then -------------------------- DEC --------------------------
		if the_rest:match("^%s*" .. REG_REGEX) then
			--dec reg
			local reg = tonumber(the_rest:match("^%s*" .. REG_REGEX_SELECT))
			
			--choose opcode
			ROM[CurrROMAddr] = 0x40 + reg
			
			CurrROMAddr = CurrROMAddr + 1
		else
			print("Bad dec operands:", the_rest)
			return false
		end
	elseif mnemonic == "db" then -------------------------- DB --------------------------
		if the_rest:match("^%s*" .. ADDR_REGEX) then
			--db byte
			local byte = tonumber(the_rest:match("^%s*" .. ADDR_REGEX_SELECT), 16)
			
			--choose opcode
			ROM[CurrROMAddr] = byte
			
			CurrROMAddr = CurrROMAddr + 1
		else
			print("Bad db operands:", the_rest)
			return false
		end
	elseif mnemonic == "inc16" then -------------------------- INC16 --------------------------
		ROM[CurrROMAddr] = 0xC0
		CurrROMAddr = CurrROMAddr + 1
	elseif mnemonic == "ret" then -------------------------- RET --------------------------
		ROM[CurrROMAddr] = 0xB9
		CurrROMAddr = CurrROMAddr + 1
	elseif mnemonic == "and" then -------------------------- AND --------------------------
		ROM[CurrROMAddr] = 0x21
		CurrROMAddr = CurrROMAddr + 1
	elseif mnemonic == "or" then -------------------------- OR --------------------------
		ROM[CurrROMAddr] = 0x19
		CurrROMAddr = CurrROMAddr + 1
	elseif mnemonic == "xor" then -------------------------- XOR --------------------------
		ROM[CurrROMAddr] = 0x29
		CurrROMAddr = CurrROMAddr + 1
	elseif mnemonic == "clr" then -------------------------- CLR --------------------------
		ROM[CurrROMAddr] = 0x28
		CurrROMAddr = CurrROMAddr + 1
	else
		print("Unrecognised instruction on line:", line)
		return false
	end
	
	return true
end

--Returns bool success
function ProcessData(line)
	--Try to process a label
	if not ProcessLabel(line) then
		--This is only an error if the line contains text that is not whitespace OR comment
		if line:match("^%s*$") or line:match("^%s*;") then
			--Not an error
			return true
		else
			print("Syntax error: did not find valid label in the data section:", line)
			return false
		end
	end
	
	return true
end

---------------------------------------- ASSEMBLER MAIN TASK ----------------------------------------

--Initialise RAM and ROM tables
for i = ROMBaseAddr, ROMBaseAddr + ROMLength do
	ROM[i] = 0
end

print("Opening " .. Assembly_file_name .. "...")

--Process all lines of the input file
err = false
for line in io.lines(Assembly_file_name) do
	--First check for the segment indicators
	if line:match("^%s*%.text") then
		CurrMode = "T"
	elseif line:match("^%s*%.data") then
		CurrMode = "D"
	elseif line:match("^%s*%.end") then
		break
	else
		--Call the appropriate handler
		if CurrMode == "T" then
			if not ProcessCode(line) then
				print("Halting assembly due to error")
				err = true
				break
			end
		elseif CurrMode == "D" then
			if not ProcessData(line) then
				print("Halting assembly due to error")
				err = true
				break
			end
		else
			print("Internal code error: CurrMode is not T or D", CurrMode)
		end
	end
end

--quit now if there was an error
if err then return end

--Post steps:


--Resolve labels
for i = ROMBaseAddr, ROMBaseAddr + ROMLength do
	--Is this an unresolved label?
	if type(ROM[i]) == "table" then
		UseCodeLabel(ROM[i][1], ROM[i][2], i)
		
		--Did it get resolved?
		if type(ROM[i]) == "table" then
			print("Cannot convert label into address:", ROM[i][1])
			err = true
			break
		end
	end
end

--quit now if there was an error
if err then return end

--Convert tables into text
for i = ROMBaseAddr, ROMBaseAddr + ROMLength do
	if not ROM[i] or type(ROM[i]) ~= "number" then
		print("Internal assembler error? ROM index " .. i .. " is incorrect type: " .. type(ROM[i]))
		err = true
		break
	end
	
	ROMtext = ROMtext .. ("%02X\n"):format(ROM[i])
end


--quit now if there was an error
if err then return end



File, e = io.open(ROM_output_file_name, "w")
if not File then
	print("Error opening ROM file:")
	print(e)
	return
end
File:write(ROMtext)
File:close()
print("ROM file written")