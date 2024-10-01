#!/bin/sh
# Building process taken from: https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/

OBJECTS_DIR=objects
EXES_DIR=exes
BINS_DIR=bins

# create needed folders 
[ -d $OBJECTS_DIR ] || mkdir -p $OBJECTS_DIR;
[ -d $EXES_DIR ] || mkdir -p $EXES_DIR;
[ -d $BINS_DIR ] || mkdir -p $BINS_DIR;

# clean folders with output files
rm -f $OBJECTS_DIR/*;
rm -f $EXES_DIR/*;
rm -f $BINS_DIR/*;

# Build the exe that will contain the shellcode in its .text section
nasm -f win64 adjuststack.asm -o $OBJECTS_DIR/adjuststack.o;
x86_64-w64-mingw32-gcc shellcode.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O0 -c -o $OBJECTS_DIR/shellcode.o -Wl,-Tlinker.ld,--no-seh;
x86_64-w64-mingw32-ld -s $OBJECTS_DIR/adjuststack.o $OBJECTS_DIR/shellcode.o -o $EXES_DIR/shellcode.exe;

# Extract the shellcode (bash built-in echo does not work)
/bin/echo -e $(for i in $(objdump -d $EXES_DIR/shellcode.exe | grep "^ " | cut -f2); do echo -n '\x'$i; done;) > $BINS_DIR/shellcode.bin && echo "Shellcode: $BINS_DIR/shellcode.bin";

# Build an exe that incorporates the shellcode imported ad position independent code
nasm -f win64 runshellcode.asm -o $OBJECTS_DIR/runshellcode.o;
x86_64-w64-mingw32-ld $OBJECTS_DIR/runshellcode.o -o $EXES_DIR/runshellcode.exe && echo "Shellcode tester exe: $EXES_DIR/runshellcode.exe";