#!/usr/bin/env python3
"""extract_mpg.py ELF OUTDIR [SECTION] : write each VIF MPG upload in an ELF section as raw microcode.

SECTION defaults to .vutext. Files are named mpg_<index>_<offset>_<vuaddress>.bin, and all.bin holds
every upload back to back. Walks the VIF stream as ImportVuMicrocode.java does: an MPG command
carries NUM 64-bit words for micro address IMMEDIATE*8, its data starts on a 64-bit boundary, and
data whose upper words set reserved bits 25-26 is not microcode.
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


def is_microcode(payload):
	return all(struct.unpack_from('<I', payload, k + 4)[0] & 0x06000000 == 0 for k in range(0, len(payload), 8))


def main():
	vutext = section(open(sys.argv[1], 'rb').read(), sys.argv[3] if len(sys.argv) > 3 else '.vutext')
	os.makedirs(sys.argv[2], exist_ok=True)
	i = count = skipped = 0
	everything = bytearray()
	while i + 4 <= len(vutext):
		code = struct.unpack_from('<I', vutext, i)[0]
		if (code >> 24) & 0x7f == 0x4a and (i + 4) % 8 == 0:
			num = (code >> 16) & 0xff or 256
			payload = vutext[i + 4:i + 4 + num * 8]
			if len(payload) == num * 8 and is_microcode(payload):
				name = 'mpg_%02d_%05x_%04x.bin' % (count, i, (code & 0xffff) * 8)
				open(os.path.join(sys.argv[2], name), 'wb').write(payload)
				everything += payload
				count += 1
				i += 4 + num * 8
				continue
			skipped += 1
		i += 4
	open(os.path.join(sys.argv[2], 'all.bin'), 'wb').write(everything)
	print(count, 'MPG uploads,', len(everything) // 8, 'instructions,', skipped, 'skipped')


main()
