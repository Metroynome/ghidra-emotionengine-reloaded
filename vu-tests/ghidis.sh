#!/bin/bash
# ghidis.sh RAW.bin OUT.txt : disassemble raw VU microcode in Ghidra headless with the repo's language.
# Builds the .sla, imports the bytes into a throwaway project with a private settings folder (so the
# installed extension is untouched) and runs DumpVU.java. VU_SLASPEC=vu0.slaspec selects VU0;
# VU_EMBED=VU0 or VU1 uses the R5900 language with that unit's microcode mode.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
GHIDRA="${GHIDRA:-D:/PS2/Ghidra/ghidra_12.0.3_PUBLIC}"
export JAVA_HOME="${JAVA_HOME:-D:/PS2/Ghidra/jdk-24.0.1}"
work="$(mktemp -d)"
spec="${VU_SLASPEC:-vu1.slaspec}"
unit="$(basename "$spec" .slaspec | tr a-z A-Z)"     # vu0.slaspec -> VU0
lang="VU:LE:32:$unit"
# VU_EMBED=VU0 or VU1 tests the microcode inside the R5900 language instead (vumicro.sinc).
if [ -n "$VU_EMBED" ]; then
	spec=r5900.slaspec
	lang="r5900:LE:32:default"
	GHIDIS_ARGS="${GHIDIS_ARGS:-} $VU_EMBED"
fi
settings="$work/settings"
ext="$settings/ghidra/$(basename "$GHIDRA")/Extensions/ghidra-emotionengine-reloaded"
mkdir -p "$ext" "$work/proj"
cp -r "$repo/data" "$repo/extension.properties" "$repo/Module.manifest" "$ext/"
sed -i 's/@extname@/ghidra-emotionengine-reloaded/; s/@extversion@/12.0.3/' "$ext/extension.properties"
(cd "$ext/data/languages" && echo | cmd //c "$(cygpath -w "$GHIDRA/support/sleigh.bat")" "$spec" > "$work/sleigh.log" 2>&1) || { tail -20 "$work/sleigh.log"; exit 1; }
grep -E "ERROR|error" "$work/sleigh.log" && exit 1 || true
export JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$(cygpath -w "$settings")"
cmd //c "$(cygpath -w "$GHIDRA/support/analyzeHeadless.bat")" "$(cygpath -w "$work/proj")" vu \
	-import "$(cygpath -w "$1")" -loader BinaryLoader -processor "$lang" -noanalysis \
	-scriptPath "$(cygpath -w "$here")" -postScript ${GHIDIS_SCRIPT:-DumpVU.java} "$(cygpath -w "$(realpath -m "$2")")" ${GHIDIS_ARGS} > "$work/headless.log" 2>&1 \
	|| { grep -E "ERROR|Exception" "$work/headless.log" | head; exit 1; }
grep -E "ERROR|Exception" "$work/headless.log" | head -5 || true
cp "$work/headless.log" "${GHIDIS_LOG:-/dev/null}" 2>/dev/null; rm -rf "$work"
