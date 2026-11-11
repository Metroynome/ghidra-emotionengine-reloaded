# Ghidra Emotion Engine: Reloaded [![run tests](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/actions/workflows/test.yml)
An extension for Ghidra that adds support for the PlayStation 2.

This extension is based on the original [ghidra-emotionengine](https://github.com/beardypig/ghidra-emotionengine) project, with a number of changes.

## Features

- Disassemble and decompile EE-specific instruction sets (MMI, VU0 macro mode, etc).
- Disassemble, decompile and emulate VU0 and VU1 micro mode code (the `VU:LE:32:VU0` and `VU:LE:32:VU1` languages). The "PS2 VU Microcode" analyzer decodes the microcode in an EE program's `.vutext` as part of auto-analysis: each microprogram becomes an overlay at its VU0 or VU1 addresses in the same program, with functions at its entry points and references from the EE code that starts it. `ImportVuMicrocode.java` does the same on demand, with a dialog of choices: elsewhere in memory, again over an earlier import, or into separate VU0/VU1 programs as well. See [vu-tests](vu-tests/README.md) for how the languages are tested and their known limits.
- Recover data types, functions and global variables from ELF files with `.mdebug` sections with the included STABS Analyzer.
- Import PCSX2 save states.
- Fix references to global variables with the MIPS-R5900 Constant Reference Analyzer.

## Installation

Release builds are available on the [releases](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases) page. Unstable builds, generated whenever there is a push to the main branch, are available [here](https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases/tag/unstable). To install the package, follow the instructions in the [Ghidra documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md#extensions).

## Building

If you want to build the extension yourself, install `gradle` and run:
 
```
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

## Common Issues

### 7-Zip returned unsupported method

Modern versions of PCSX2 store save states using zstd compression by default, which Ghidra's zip implementation doesn't support. To work around this, if you are using PCSX2 v2.1.178 or higher you should make sure that `Tools -> Show Advanced Settings` is checked, then navigate to `File -> Settings -> Advanced -> Savestate Settings` and change the `Compression Method` option to `Deflate64`. If you are using an older version, you will have to change `SavestateZstdCompression` to `false` in the `EmuCore` section of your `PCSX2.ini` file.

### Decompilation fails for some functions

Try disabling the `Decompiler Parameter ID` analyzer.

### Symbols aren't being demangled

Enable the `Use Deprecated Demangler` option in the settings for the `Demangler GNU` analyzer.
