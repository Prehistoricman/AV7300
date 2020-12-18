.data
char1 = #E501:
space1:
char2:
space2:
char3:
space3:
char4:
space4:
char5:
space5: ;Readout ptr

arg1 = #E81A:
ret1:
ret2:

.text
LED_ROUTINE = #D599:

mov R0, #55; ;12 bytes to play with
mov R1, #55;
mov R2, #55;
mov R3, #55;
mov R4, #55;
mov R5, #55;

;Output vars to memory
mov char1, R0
mov space1, R1
mov char2, R2
mov space2, R3
mov char3, R4
mov space3, R5
mov char4, R6
mov space4, R7

;Choose what address to output
mov R0, space5
jz dummyreadout
mov R2, space5 ;LSB
mov R3, #E5 ;MSB
db #F2 ; Indrect load here
jmp startBlink

dummyreadout:
mov R0, #FF

startBlink:
mov arg1, R0
call BlinkData

mov R2, space5
inc R2
mov R0, #09
cmp R0, R2
jne skipReset
mov R2, #0
skipReset:
mov space5, R2

ret



BASE = #E820:
; Replace LED routine with this if we run out of space in the ISR
; Injection point: E0 D5 C8 81 CE E0 99 @ 0x0B6D (file) or 0xD6D2 (memory)


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