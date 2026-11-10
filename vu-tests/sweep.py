#!/usr/bin/env python3
"""sweep.py OUT.bin [SAMPLES] : random VU instructions covering every opcode-field value.

For each upper opcode (bits 0-5, plus bits 6-10 for the special group) and each lower opcode
(bits 25-31, plus bits 0-10 for the 0x40 group), emit SAMPLES words with random operand bits, and
some with operand bits all clear, so the reference disassembler shows every form it accepts.
The other half is a NOP: upper 0x000002ff, lower 0x8000033c.
"""
import random
import struct
import sys

UPPER_NOP, LOWER_NOP = 0x000002ff, 0x8000033c
samples = int(sys.argv[2]) if len(sys.argv) > 2 else 24
rng = random.Random(1)
pairs = []


def variants(fixed, fixed_mask, free_mask):
	yield fixed
	for _ in range(samples):
		yield fixed | (rng.getrandbits(32) & free_mask & ~fixed_mask)


UPPER_FREE = 0x07ffffff        # flag bits 27-31 stay clear here
for op in range(64):
	for w in variants(op, 0x3f, UPPER_FREE):
		pairs.append((LOWER_NOP, w))
for op2 in range(32):
	for lo in range(4):
		fixed = op2 << 6 | 0x3c | lo
		for w in variants(fixed, 0x7ff, UPPER_FREE):
			pairs.append((LOWER_NOP, w))
for op in range(128):
	if op == 0x40:
		continue
	for w in variants(op << 25, 0xfe000000, 0xffffffff):
		pairs.append((w, UPPER_NOP))
for op in range(64):
	for w in variants(0x40 << 25 | op, 0xfe00003f, 0xffffffff):
		pairs.append((w, UPPER_NOP))
for op2 in range(32):
	for lo in range(4):
		fixed = 0x40 << 25 | op2 << 6 | 0x3c | lo
		for w in variants(fixed, 0xfe0007ff, 0xffffffff):
			pairs.append((w, UPPER_NOP))
# The flag bits of the upper word, with an ordinary instruction.
for flags in range(32):
	pairs.append((LOWER_NOP, flags << 27 | 0x2ff))
with open(sys.argv[1], 'wb') as f:
	for lower, upper in pairs:
		f.write(struct.pack('<II', lower, upper))
print(len(pairs), 'instructions')
