#!/bin/bash
# checkgame.sh ELF NAME : check a game's VU microcode end to end.
#   1. extract_mpg.py pulls every MPG upload out of .vutext into corpus_NAME/ (all.bin holds them all)
#   2. refdis.py disassembles them with dvp-objdump, in the PS2SDK container ($CONTAINER)
#   3. ghidis.sh disassembles them with the repo's language; compare.py diffs the two
#   4. ghrun.sh imports the ELF with ImportVuMicrocode.java and decompiles every function
# Outputs (corpus_NAME*, imp_NAME.log) are gitignored: game microcode is never committed.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
elf="$1"; name="$2"
CONTAINER="${CONTAINER:-projectryno-svo75}"
cd "$here"
python -I extract_mpg.py "$elf" "corpus_$name"
# A trailing nop gives the last instruction's delay slot something to decode.
cp "corpus_$name/all.bin" "corpus_$name.bin"
printf '\x3c\x03\x00\x80\xff\x02\x00\x00' >> "corpus_$name.bin"
MSYS_NO_PATHCONV=1 docker exec "$CONTAINER" mkdir -p /tmp/vu
docker cp refdis.py "$CONTAINER:/tmp/vu/" >/dev/null
docker cp "corpus_$name.bin" "$CONTAINER:/tmp/vu/" >/dev/null
MSYS_NO_PATHCONV=1 docker exec -w /tmp/vu "$CONTAINER" python3 refdis.py "corpus_$name.bin" "corpus_${name}_ref.txt" >/dev/null
docker cp "$CONTAINER:/tmp/vu/corpus_${name}_ref.txt" . >/dev/null
bash ghidis.sh "corpus_$name.bin" "corpus_${name}_gh.txt" >/dev/null
echo "disassembly: $(python compare.py "corpus_${name}_ref.txt" "corpus_${name}_gh.txt" | tail -1)"
GHRUN_LOG="imp_$name.log" bash ghrun.sh "$elf" ImportVuMicrocode.java VU1 verify
grep -h 'became\|Resident\|EE code\|VERIFY\|Skipped\|flows to\|ERROR' "imp_$name.log" \
	| sed 's/^INFO  ImportVuMicrocode.java> /import: /; s/ (GhidraScript) *$//'
