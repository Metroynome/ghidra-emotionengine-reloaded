#!/usr/bin/env python3
"""compare.py REF.txt GHIDRA.txt : diff Ghidra's VU disassembly against the reference dvp-objdump.

Both files are `ADDRESS<tab>LOWERHEX UPPERHEX<tab>TEXT...`. Text must match exactly except:
- whitespace is collapsed;
- the reference appends `<symbol+offset>` to branch targets, which is dropped;
- numbers are compared by value, because SLEIGH prints computed immediates in hex;
- `loi` operands: Ghidra shows the raw word, formatted here with %g as the reference does.
Exit status is 0 only when every instruction matches.
"""
import collections
import re
import struct
import sys

NUM = re.compile(r'(?<![\w.])(-?0x[0-9a-fA-F]+|-?[0-9]+)(?![\w.])')


def normalize(text, branch_hex):
	text = re.sub(r'\s*<[^>]*>', '', text)
	text = re.sub(r'\s+', ' ', text).strip()
	m = re.search(r'\bloi (\S+)$', text)
	if m and m[1].startswith('0x'):
		bits = int(m[1], 16)
		value = struct.unpack('<f', struct.pack('<I', bits))[0]
		# C's printf("%g") keeps the sign of a NaN; Python's does not.
		shown = ('-nan' if bits >> 31 else 'nan') if value != value else '%g' % value
		text = text[:m.start(1)] + shown
	if branch_hex:
		# The reference prints branch targets in hex without a prefix: make them explicit.
		text = re.sub(r'(?<=[ ,])([0-9a-f]+)$', lambda x: '0x' + x[1], text)
	return NUM.sub(lambda x: str(int(x[1], 16 if 'x' in x[1] else 10)), text)


def is_branch(text):
	return re.match(r'(\S+\s+)?(b|bal|ibeq|ibne|ibltz|ibgtz|iblez|ibgez)\b', text.split('\t')[-1]) is not None


def load(path):
	rows = {}
	for line in open(path):
		f = line.rstrip('\n').split('\t')
		rows[f[0]] = (f[1], '\t'.join(f[2:]))
	return rows


def main():
	ref = load(sys.argv[1])
	gh = load(sys.argv[2])
	bad = collections.defaultdict(list)
	total = 0
	for addr, (words, text) in ref.items():
		total += 1
		other = gh.get(addr, (None, '<missing>'))[1]
		branch = is_branch(text)
		a = normalize(text, branch)
		b = normalize(other, False)
		if a != b:
			key = re.sub(r'[.\[].*', '', a.split(' ')[0]) + ' | ' + (a.split(' ', 1)[1].split(' ')[0] if ' ' in a else '')
			bad[re.sub(r'[.\[].*', '', a.split(' ')[0])].append((addr, words, text, other))
	n = sum(len(v) for v in bad.values())
	print('%d / %d match' % (total - n, total))
	for k, v in sorted(bad.items(), key=lambda kv: -len(kv[1]))[:40]:
		addr, words, text, other = v[0]
		print('%5d %-10s %s\n      ref: %s\n      gh:  %s' % (len(v), k, words, text, other))
	sys.exit(1 if n else 0)


main()
