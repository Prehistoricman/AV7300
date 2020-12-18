.data
char1 = #E501: #0
space1: #0
char2 = #E503: #0
space2: #0
char3 = #E505: #0
char4 = #E507: #0
char5 = #E509: #0

arg1 = #E81A: #0
ret1: #0
ret2: #0

.text
BASE: ;0xE820
; Injection point: E0 E8 C8 81 CE E0 20 @ 0x0B6D (file) or 0xD6D2 (memory)
; This program will read out the memory space to the LED
; Adjust the constants in the 08 section to increase readout rate (0x0030 has been tested, 60 bytes/s)

; Input values
mov R2, space1 ;LSB
mov R3, space2 ;MSB
db #F2 ;Indrect load here
mov arg1, R0
db #5D ;Disable interrupts
call BlinkData
db #6D ;Enable interrupts

mov R0, space1
mov R1, space2
inc16
mov space1, R0
mov space2, R1
ret


BlinkData:
mov R1, arg1
mov R2, #8 ;Loop counter

;Blink to say hi to the Arduino
mov R0, #0
mov [#F102], R0
mov R0, #80
mov [#F102], R0


loop:
mov R0, #1
and
jz bitlow
mov R0, #0
mov [#F102], R0
jmp next
bitlow:
mov R0, #80
mov [#F102], R0
mov R0, R0 ;NOP to equalise time between low and high
mov R0, R0 ;NOP to equalise time between low and high
mov R0, R0 ;NOP to equalise time between low and high

next:
rshift R1
dec R2
mov R0, R2
jnz loop


mov R0, #80
mov R0, #80
mov R0, #80
mov R0, #80
mov R0, #80
mov [#F102], R0
ret