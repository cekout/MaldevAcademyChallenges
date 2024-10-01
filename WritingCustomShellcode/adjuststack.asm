; Entrypoint for the shellcode, it simply aligns the stack and calls the effective entrypoint
; Part of code and ideas taken from https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
; To compile use: nasm -f win64 adjuststack.asm -o adjuststack.o

extern entrypoint
global alignstack

segment .text

alignstack:
	push rbp,						; save rbp
	mov rbp, rsp					; save current stack frame start into rbp
	and rsp, 0xfffffffffffffff0		; stack alignment
	call entrypoint					; call "real"
	mov rsp, rbp					; restore rsp, skipping alignment
	pop rbp							; restore rbp
	ret
