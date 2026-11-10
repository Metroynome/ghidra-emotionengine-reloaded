#!/usr/bin/env python3
"""mktests.py IN.vut OUT.txt : assemble each test's `asm` lines with dvp-as into EmuVU `code` lines.

Run in a container with PS2SDK's dvp binutils. Label lines ("name:") pass through to the assembler,
so branches can name their targets. Other directives are copied unchanged.
"""
import re
import subprocess
import struct
import sys
import tempfile

DVP = '/opt/ps2dev/dvp/bin/'


def assemble(lines):
	work = tempfile.mkdtemp()
	with open(work + '/t.vsm', 'w') as f:
		f.write('\t.vu\n' + ''.join(l + '\n' for l in lines))
	r = subprocess.run([DVP + 'dvp-as', '-o', work + '/t.o', work + '/t.vsm'], capture_output=True, text=True)
	if r.returncode:
		raise SystemExit(r.stderr)
	subprocess.run([DVP + 'dvp-objcopy', '-O', 'binary', '-j', '.vutext', work + '/t.o', work + '/t.bin'], check=True)
	data = open(work + '/t.bin', 'rb').read()
	return [struct.unpack_from('<II', data, i) for i in range(0, len(data), 8)]


def main():
	out = []
	block = []
	for raw in open(sys.argv[1]):
		line = raw.rstrip('\n')
		stripped = re.sub(r'#.*', '', line).strip()
		if line.startswith('asm\t'):
			block.append('\t' + line[4:])
		elif re.fullmatch(r'\w+:', stripped):
			block.append(stripped)
		elif stripped.startswith('test '):
			out.append(stripped)
		elif stripped == 'run':
			for lower, upper in assemble(block) if block else []:
				out.append('code 0x%08x 0x%08x' % (lower, upper))
			out.append('run')
			block = []
		elif stripped:
			out.append(stripped)
	open(sys.argv[2], 'w').write('\n'.join(out) + '\n')
	print(sum(1 for l in out if l.startswith('test ')), 'tests')


main()
