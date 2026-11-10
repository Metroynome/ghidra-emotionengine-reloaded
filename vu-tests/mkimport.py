#!/usr/bin/env python3
"""mkimport.py OUT.elf : build a small EE ELF that exercises ImportVuMicrocode.java.

Run in a container with PS2SDK (dvp-as, ee-as, ee-ld). The ELF's .vutext holds three DMA chains:
  A  uploads VU 0x000-0x027; its code branches to 0x100, outside its own upload.
  B  uploads VU 0x100-0x117, the only upload there, so the import adds it to A's overlay.
  C  uploads VU 0x000-0x017 again, so it is a separate microprogram.
Its .text has an EE function that builds MSCAL 0x108 and points at chain B, so B gets a function
at 0x108 noting the EE call, and one that builds MSCALF 0x100 with no chain, which still belongs to
B because B is the only upload covering 0x100.
"""
import os
import struct
import subprocess
import sys
import tempfile

DVP = '/opt/ps2dev/dvp/bin/'
EE = '/opt/ps2dev/ee/bin/'


def run(*cmd):
	subprocess.run(cmd, check=True)


def microcode(work, lines):
	with open(work + '/m.vsm', 'w') as f:
		f.write('\t.vu\n' + ''.join('\t' + l + '\n' for l in lines))
	run(DVP + 'dvp-as', '-o', work + '/m.o', work + '/m.vsm')
	run(DVP + 'dvp-objcopy', '-O', 'binary', '-j', '.vutext', work + '/m.o', work + '/m.bin')
	return open(work + '/m.bin', 'rb').read()


def chain(label, vuaddr, code):
	"""One DMA END chain: tag, VIF NOP, VIF MPG, then the code (64-bit aligned)."""
	n = len(code) // 8
	qwc = (8 + len(code) + 15) // 16
	words = [0x70000000 | qwc, 0, 0, 0x4a000000 | (n << 16) | (vuaddr // 8)]
	words += struct.unpack('<%dI' % (len(code) // 4), code)
	while len(words) % 4:
		words.append(0)
	return '%s:\n' % label + ''.join('\t.word 0x%08x\n' % w for w in words)


def main():
	work = tempfile.mkdtemp()
	# Each program ends with an E bit and the instruction after it, as real uploads do.
	full = microcode(work, ['NOP\tIADDIU VI01, VI00, 1', 'NOP\tB target', 'NOP\tNOP', 'NOP[E]\tNOP'] +
		['NOP\tNOP'] * 28 + ['target:', 'NOP\tIADDIU VI02, VI00, 2', 'NOP[E]\tNOP', 'NOP\tNOP'])
	a, b = full[:0x28], full[0x100:0x118]
	c = microcode(work, ['NOP\tIADDIU VI03, VI00, 3', 'NOP[E]\tNOP', 'NOP\tNOP'])
	asm = ['\t.set noreorder', '\t.section .vutext,"a"', '\t.align 4',
		chain('chain_a', 0, a), chain('chain_b', 0x100, b), chain('chain_c', 0, c),
		'\t.text', '\t.globl start_b', 'start_b:',
		'\tlui $t7, 0x1400', '\tlui $t4, %hi(0x108)', '\taddiu $t4, $t4, %lo(0x108)', '\tsra $t4, $t4, 3',
		'\tor $t4, $t4, $t7', '\tlui $t1, %hi(chain_b)', '\taddiu $t1, $t1, %lo(chain_b)',
		'\tsw $t4, 0($t1)', '\tjr $ra', '\tnop',
		'\t.globl start_any', 'start_any:',
		'\tlui $t0, 0x1500', '\tori $t0, $t0, 0x20', '\tsw $t0, 0($a0)', '\tjr $ra', '\tnop']
	with open(work + '/t.s', 'w') as f:
		f.write('\n'.join(asm) + '\n')
	run(EE + 'ee-as', '-o', work + '/t.o', work + '/t.s')
	run(EE + 'ee-ld', '-e', 'start_b', '-Ttext', '0x200000', '--section-start', '.vutext=0x100000',
		'-o', sys.argv[1], work + '/t.o')
	print('wrote', sys.argv[1])


main()
