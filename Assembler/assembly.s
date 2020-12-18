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

mov R2, space1 ;LSB
mov R3, space2 ;MSB
db #F2 ; Indrect load here
mov arg1, R0
db #5D
call BlinkData
db #6D
mov R0, space1
mov R1, space2
inc16
mov space1, R0
mov space2, R1
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