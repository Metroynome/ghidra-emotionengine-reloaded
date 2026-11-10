#!/usr/bin/env python3
"""bitflip.py make REF_SWEEP.txt OUT.bin | analyze REF_FLIPS.txt

make: for one valid word of every mnemonic in each half, emit the word with each bit flipped in turn.
analyze: report, per mnemonic, which bits must be clear (or set) for the reference to decode it.
"""
import collections
import re
import struct
import sys

UPPER_NOP, LOWER_NOP = 0x000002ff, 0x8000033c


def word(hexle):
	return struct.unpack('<I', bytes.fromhex(hexle))[0]


def mnemonic(text):
	return re.sub(r'[\[.].*', '', text.split(' ')[0])


if sys.argv[1] == 'make':
	seen = {}
	for line in open(sys.argv[2]):
		f = line.rstrip('\n').split('\t')
		lo, up = f[1].split()
		for half, text, w in (('U', f[2], word(up)), ('L', f[3], word(lo))):
			m = mnemonic(text)
			if m in ('*unknown*', 'nop', 'loi'):
				continue
			seen.setdefault((half, m), w)
	with open(sys.argv[3], 'wb') as out:
		for (half, m), w in sorted(seen.items()):
			for bit in range(32):
				if half == 'U' and bit >= 27:
					continue        # flag bits; tested separately
				v = w ^ (1 << bit)
				pair = (LOWER_NOP, v) if half == 'U' else (v, UPPER_NOP)
				out.write(struct.pack('<II', *pair))
			pair = (LOWER_NOP, w) if half == 'U' else (w, UPPER_NOP)
			out.write(struct.pack('<II', *pair))
	print(len(seen), 'forms')
else:
	groups = collections.defaultdict(list)
	rows = [l.rstrip('\n').split('\t') for l in open(sys.argv[2])]
	i = 0
	while i < len(rows):
		# Each form is 32 (lower) or 27 (upper) flips followed by the original.
		for n in (27, 32):
			if i + n < len(rows):
				orig = rows[i + n]
				lo, up = orig[1].split()
				half = 'U' if word(lo) == LOWER_NOP and word(up) != UPPER_NOP else 'L'
				if (half == 'U' and n == 27) or (half == 'L' and n == 32):
					base = word(up) if half == 'U' else word(lo)
					text = orig[2] if half == 'U' else orig[3]
					reject = 0
					for k in range(n):
						t = rows[i + k][2] if half == 'U' else rows[i + k][3]
						if mnemonic(t) == '*unknown*':
							reject |= 1 << k
					must_clear = reject & ~base
					must_set = reject & base
					groups[(half, mnemonic(text))] = (base, must_clear, must_set, text)
					i += n + 1
					break
		else:
			i += 1
	for (half, m), (base, clear, setb, text) in sorted(groups.items()):
		print('%s %-9s base=%08x mustclear=%08x mustset=%08x  %s' % (half, m, base, clear, setb, text))
