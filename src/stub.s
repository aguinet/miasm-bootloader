bits 16                 ;16-bit mode
org 0x82A8

start:
pusha 

lea di, [bp-0x44]
lea bx, [0x674A]
xor cx,cx

loop:
mov eax, dword [bx]
mov dword [di], eax
add di, 4
add bx, 4
inc cx
cmp cx,8
jnz loop

popa
jmp 0x835A
