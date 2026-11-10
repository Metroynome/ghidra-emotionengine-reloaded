#!/usr/bin/env python3
"""refdis.py RAW.bin OUT.txt : disassemble raw VU microcode with the reference dvp-objdump.

dvp-objdump only decodes VU code after a `.vu.N` mapping symbol, which only dvp-as emits. So this
assembles a block of NOP pairs of the same size and patches the raw bytes into its .vutext.
Output lines are `ADDRESS<tab>LOWERHEX UPPERHEX<tab>DISASSEMBLY`. Needs PS2SDK's dvp binutils.
"""
import re
import subprocess
import sys
import tempfile

DVP = '/opt/ps2dev/dvp/bin/'


def section_offset(obj, name):
    out = subprocess.run([DVP + 'dvp-objdump', '-h', obj], capture_output=True, text=True, check=True).stdout
    m = re.search(r'\s%s\s+([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+\s+([0-9a-f]+)' % re.escape(name), out)
    return int(m[2], 16), int(m[1], 16)


def main():
    raw = open(sys.argv[1], 'rb').read()
    assert len(raw) % 8 == 0
    work = tempfile.mkdtemp()
    with open(work + '/p.vsm', 'w') as f:
        f.write('\t.vu\n' + '\tNOP\tNOP\n' * (len(raw) // 8))
    subprocess.run([DVP + 'dvp-as', '-o', work + '/p.o', work + '/p.vsm'], check=True)
    offset, size = section_offset(work + '/p.o', '.vutext')
    assert size == len(raw), (size, len(raw))
    obj = bytearray(open(work + '/p.o', 'rb').read())
    obj[offset:offset + size] = raw
    open(work + '/p.o', 'wb').write(obj)
    dis = subprocess.run([DVP + 'dvp-objdump', '-d', work + '/p.o'], capture_output=True, text=True, check=True).stdout
    out = []
    lines = [l for l in dis.splitlines() if re.match(r'\s+[0-9a-f]+:\t', l)]
    for i in range(0, len(lines) - 1, 2):
        a = lines[i].split('\t')
        b = lines[i + 1].split('\t')
        address = int(a[0].strip().rstrip(':'), 16)
        # The upper and lower halves are separate tab-delimited fields.
        text = '\t'.join(re.sub(r'\s+', ' ', x.strip()) for x in a[2:4])
        out.append('%04x\t%s %s\t%s' % (address, a[1].strip().replace(' ', ''), b[1].strip().replace(' ', ''), text))
    open(sys.argv[2], 'w').write('\n'.join(out) + '\n')
    print(len(out), 'instructions')


main()
