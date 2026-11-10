#!/usr/bin/env python3
"""extract_mpg.py ELF OUTDIR : write each VIF MPG upload in an ELF's .vutext as raw microcode.

Files are named mpg_<index>_<offset>_<vuaddress>.bin. Walks the VIF stream: MPG carries NUM
64-bit words for micro address IMMEDIATE*8. Other VIF codes are skipped by their size.
"""
import os
import struct
import sys


def section(data, want):
    shoff = struct.unpack_from('<I', data, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 46)
    headers = [struct.unpack_from('<10I', data, shoff + i * shentsize) for i in range(shnum)]
    names = headers[shstrndx]
    for h in headers:
        name = data[names[4] + h[0]:data.index(0, names[4] + h[0])].decode()
        if name == want:
            return data[h[4]:h[4] + h[5]]
    raise SystemExit('no section ' + want)


def main():
    vutext = section(open(sys.argv[1], 'rb').read(), '.vutext')
    os.makedirs(sys.argv[2], exist_ok=True)
    i = count = 0
    while i + 4 <= len(vutext):
        code = struct.unpack_from('<I', vutext, i)[0]
        if (code >> 24) & 0x7f == 0x4a:
            num = (code >> 16) & 0xff or 256
            payload = vutext[i + 4:i + 4 + num * 8]
            name = 'mpg_%02d_%05x_%04x.bin' % (count, i, (code & 0xffff) * 8)
            open(os.path.join(sys.argv[2], name), 'wb').write(payload)
            count += 1
            i += 4 + num * 8
        else:
            i += 4
    print(count, 'MPG uploads')


main()
