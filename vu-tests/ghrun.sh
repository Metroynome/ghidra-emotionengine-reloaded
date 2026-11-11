#!/bin/bash
# ghrun.sh FILE SCRIPT [ARGS...] : build the extension, install it in a private settings folder (the
# real Ghidra install is untouched), import FILE with its normal loader and run a shipped script.
# The headless log goes to ${GHRUN_LOG:-ghrun.log}.
# GHRUN_IMPORT_ARGS adds import options, e.g. "-loader BinaryLoader -processor r5900:LE:32:default"
# for a raw EE memory dump. GHRUN_ANALYZE=1 runs auto-analysis before the script.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
GHIDRA="${GHIDRA:-D:/PS2/Ghidra/ghidra_12.0.3_PUBLIC}"
export JAVA_HOME="${JAVA_HOME:-D:/PS2/Ghidra/jdk-24.0.1}"
file="$1"; script="$2"; shift 2
(cd "$repo" && GHIDRA_INSTALL_DIR="$GHIDRA" gradle buildExtension --no-daemon -q) >/dev/null
work="$(mktemp -d)"
settings="$work/settings"
ext="$settings/ghidra/$(basename "$GHIDRA")/Extensions"
mkdir -p "$ext" "$work/proj"
# dist/ may hold builds for several Ghidra versions; take the newest for this one.
zip="$(ls -t "$repo/dist/$(basename "$GHIDRA")"_*.zip | head -1)"
(cd "$ext" && unzip -q "$zip")
export JAVA_TOOL_OPTIONS="-Dapplication.settingsdir=$(cygpath -w "$settings")"
cmd //c "$(cygpath -w "$GHIDRA/support/analyzeHeadless.bat")" "$(cygpath -w "$work/proj")" test \
	-import "$(cygpath -w "$file")" ${GHRUN_IMPORT_ARGS} $([ -n "$GHRUN_ANALYZE" ] || echo -noanalysis) -postScript "$script" "$@" > "${GHRUN_LOG:-ghrun.log}" 2>&1 || true
rm -rf "$work"
