.data
char1 = #E501: #0
char2 = #E503: #0
char3 = #E505: #0
char4 = #E507: #0
char5 = #E509: #0

arg1 = #E81A: #0
ret1: #0
ret2: #0

.text
BASE: ;0xE820
; Injection point: EC C0 E7 @ 0x0B2D (file) or 0xD692 (memory)
; This program will read out two bytes (from R0 and R1) to the USB descriptor strings on boot

; Input values
mov R0, #E8
mov R1, #BF
mov R0, #E8
mov R1, #BF ;8 bytes dummy space

push R1 ;Keep R1 handy

mov arg1, R0
call PrintHex
mov R0, ret1
mov char1, R0
mov R0, ret2
mov char2, R0

mov R0, #20
mov char3, R0

pop R0 ;Load R1 from earlier

mov arg1, R0
call PrintHex
mov R0, ret1
mov char4, R0
mov R0, ret2
mov char5, R0

MOV     R4, [#E7C0] ;original code
ret




PrintHex:
mov R0, #9F
mov R1, arg1 ;load input
cmp R0, R1
jc LowerSet1 ;Jump if input <= 9F
;If the first letter is from A-F
mov R0, #3F
mov ret1, R0 ;Load letter A - 2
mov R0, #40 ;Is 40 bit present?
and
jz Not40_1
;Letter is from A-F and contains 40
mov R0, #43 ;3F + 4
mov ret1, R0
Not40_1:
mov R0, #20
and
jz Not20_1
mov R0, ret1
inc R0
inc R0
mov ret1, R0
Not20_1:
mov R0, #10
and
jz Not10_1
mov R0, ret1
inc R0
mov ret1, R0
Not10_1:
jmp SecondChar
;First char 

LowerSet1:
mov R0, #30 ;Char for 0
mov ret1, R0
mov R0, #80
and
jz Not80_2
mov R0, #38 ;Char for 8
mov ret1, R0
Not80_2:
mov R0, #40
and
jz Not40_2
;Letter is from 0-7 and contains 40
mov R0, #34 ;Char for 4
mov ret1, R0
Not40_2:
mov R0, #20
and
jz Not20_2
mov R0, ret1
inc R0
inc R0
mov ret1, R0
Not20_2:
mov R0, #10
and R0
jz SecondChar
mov R0, ret1
inc R0
mov ret1, R0


SecondChar:


mov R1, arg1 ;Cut off upper bits from input
mov R0, #F
and
mov arg1, R0
mov R1, arg1 ;Reload input
mov R0, #9
cmp R0, R1
jc LowerSet1_2 ;Jump if 9 >= input
;If the first letter is from A-F
mov R0, #3F
mov ret2, R0 ;Load letter A - 2
mov R0, #4
and
jz Not40_1_2
;Letter is from A-F and contains 40
mov R0, #43 ;3F + 4
mov ret2, R0
Not40_1_2:
mov R0, #2
and
jz Not20_1_2
mov R0, ret2
inc R0
inc R0
mov ret2, R0
Not20_1_2:
mov R0, #1
and
jz Not10_1_2
mov R0, ret2
inc R0
mov ret2, R0
Not10_1_2:
jmp done
;First char

LowerSet1_2:
mov R0, #30 ;Char for 0
mov ret2, R0
mov R0, #8
and
jz Not80_2_2
mov R0, #38 ;Char for 8
mov ret2, R0
Not80_2_2:
mov R0, #4
and
jz Not40_2_2
;Letter is from 0-7 and contains 40
mov R0, #34 ;Char for 4
mov ret2, R0
Not40_2_2:
mov R0, #2
and
jz Not20_2_2
mov R0, ret2
inc R0
inc R0
mov ret2, R0
Not20_2_2:
mov R0, #1
and
jz done
mov R0, ret2
inc R0
mov ret2, R0

done:
ret