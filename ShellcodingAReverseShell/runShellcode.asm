; Test program, just import shellcode in .text section 
; compile with:
; nasm -f win64 runshellcode.asm -o objects/runshellcode.o
; x86_64-w64-mingw32-ld objects/runshellcode.o -o exes/runshellcode.exe

Global Start

Start:
    ;int3 ;uncomment for debugging
    incbin "bins/shellcode.bin"
