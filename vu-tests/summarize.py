#!/usr/bin/env python3
"""summarize.py REF.txt : list every distinct upper and lower mnemonic in reference output."""
import collections
import re
import sys

up = collections.Counter()
lo = collections.Counter()
for line in open(sys.argv[1]):
	f = line.rstrip('\n').split('\t')
	if len(f) > 2:
		up[re.sub(r'\[.*?\]', '', f[2].split(' ')[0])] += 1
	if len(f) > 3:
		lo[re.sub(r'\[.*?\]', '', f[3].split(' ')[0])] += 1
for name, c in (('upper', up), ('lower', lo)):
	print(name, len(c), ' '.join(sorted(c)))
