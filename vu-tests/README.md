# VU micro mode tests

These tests check the `PS2-VU` languages (`VU:LE:32:VU0` and `VU:LE:32:VU1`) against PS2SDK's `dvp-as` and `dvp-objdump`, the GNU toolchain for VU microcode. The reference tools run in a container that has PS2SDK; Ghidra runs headless on the host, using a private settings folder so an installed copy of the extension is never touched.

The language source is generated: edit `gen_slaspec.py`, then run `python gen_slaspec.py vu1 ../data/languages/vu1.slaspec` and the same for `vu0`.

## Disassembly

| Step | Tool |
|---|---|
| Reference text | `refdis.py RAW OUT` disassembles raw microcode with `dvp-objdump` |
| Ghidra text | `ghidis.sh RAW OUT` disassembles it with the repo's language (`DumpVU.java`) |
| Diff | `compare.py REF GHIDRA` must report every instruction matching |

Corpora:
- `sweep.py` writes one instruction per opcode value with random operand bits, which also covers each instruction's reserved fields. `bitflip.py` measured those fields.
- A fully random corpus of 64-bit words covers flag bits, invalid halves and unusual sequences.
- `extract_mpg.py ELF DIR` pulls a game's microcode out of `.vutext`. Game microcode is never committed (see `.gitignore`).

`compare.py` allows only these differences, all because SLEIGH cannot print otherwise: whitespace, the reference's `<symbol+offset>` after branch targets, computed immediates in hex (`iaddiu`, `fs*`), and `loi` showing the raw word (compared through `%g`, as the reference prints it).

## Semantics

`semantics.vut` holds emulator tests in `dvp-as` syntax. `mktests.py` assembles them, and `EmuVU.java` runs each one in Ghidra's p-code emulator and checks the registers and VU memory it names:

```
python mktests.py semantics.vut semantics_built.txt     # in the container
GHIDIS_SCRIPT=EmuVU.java GHIDIS_ARGS=semantics_built.txt bash ghidis.sh blank.bin result.txt
```

## Import

`ghrun.sh ELF ImportVuMicrocode.java VU1 verify` builds the extension, imports an EE ELF, creates the VU program from its `.vutext` and decompiles every function.

## Known limits

- Pipeline timing is not modelled: Q and P results arrive immediately, and there are no stalls.
- MAC and status flags are not set by arithmetic; flag instructions read the flag registers as they stand.
- EFU transcendentals (`esin`, `eatan`, `eatanxy`, `eatanxz`, `eexp`), `rnext` and `xgkick` are opaque p-code operations.
