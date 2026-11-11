#!/bin/bash
# runall.sh : every VU check that needs no game file of yours beyond the corpora below.
#   Disassembly: each corpus (sweep, dense, rand and any corpus_<game>.bin with its _ref.txt),
#   standalone VU1 and inside R5900 (VU1 and VU0 micro mode), against dvp-objdump's reference text.
#   Semantics: semantics_built.txt in the emulator, standalone VU1 and VU0, and inside R5900.
# Each run imports into a throwaway project with a private settings folder. A language that fails to
# compile stops the run, so stale output can never pass.
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
[ -f blank.bin ] || python -c "open('blank.bin', 'wb').write(bytes(1024))"
fail=0
check() {   # check NAME COMMAND... : run, then require the output file to be new
	local name="$1" out="$2"; shift 2
	rm -f "$out"
	if ! "$@" >/dev/null 2>&1 || [ ! -s "$out" ]; then
		echo "$name: FAILED (see ghidis.sh output)"; fail=1; return 1
	fi
}
for ref in sweep_ref.txt dense_ref.txt rand_ref.txt corpus_*_ref.txt; do
	[ -f "$ref" ] || continue
	bin="${ref%_ref.txt}.bin"
	[ "$bin" = corpus_dl.bin ] && bin=corpus_dl_all.bin
	[ -f "$bin" ] || { echo "$ref: no $bin"; continue; }
	for mode in standalone VU1 VU0; do
		out="$bin.$mode.gh.txt"
		if [ $mode = standalone ]; then check "$bin $mode" "$out" bash ghidis.sh "$bin" "$out" || continue
		else VU_EMBED=$mode check "$bin $mode" "$out" bash ghidis.sh "$bin" "$out" || continue; fi
		result="$(python compare.py "$ref" "$out" | tail -1)"
		echo "disassembly $bin ($mode): $result"
		case "$result" in *" / "*) [ "$(echo "$result" | awk '{print $1}')" = "$(echo "$result" | awk '{print $3}')" ] || fail=1;; *) fail=1;; esac
	done
done
for mode in vu1 vu0 VU1 VU0; do
	out="emu_$mode.txt"
	case $mode in
		vu1) check "emulator standalone VU1" "$out" env GHIDIS_SCRIPT=EmuVU.java GHIDIS_ARGS=semantics_built.txt bash ghidis.sh blank.bin "$out" ;;
		vu0) check "emulator standalone VU0" "$out" env VU_SLASPEC=vu0.slaspec GHIDIS_SCRIPT=EmuVU.java GHIDIS_ARGS=semantics_built.txt bash ghidis.sh blank.bin "$out" ;;
		*) check "emulator R5900 $mode" "$out" env VU_EMBED=$mode GHIDIS_SCRIPT=EmuVU.java GHIDIS_ARGS=semantics_built.txt bash ghidis.sh blank.bin "$out" ;;
	esac || continue
	echo "emulator $mode: $(tail -1 "$out")"
	grep -q "failed 0" "$out" || fail=1
done
[ $fail = 0 ] && echo "ALL PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
