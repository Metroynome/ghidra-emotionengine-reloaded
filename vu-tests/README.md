# VU micro mode tests

These tests check VU micro mode, both inside the R5900 language (`vumicro.sinc`, where the `VUMODE` context selects VU0 or VU1) and in the standalone `PS2-VU` languages (`VU:LE:32:VU0` and `VU:LE:32:VU1`), against PS2SDK's `dvp-as` and `dvp-objdump`, the GNU toolchain for VU microcode. The reference tools run in a container that has PS2SDK; Ghidra runs headless on the host, using a private settings folder so an installed copy of the extension is never touched.

The language source is generated: edit `gen_slaspec.py`, then run `python gen_slaspec.py embed ../data/languages/vumicro.sinc`, `python gen_slaspec.py vu1 ../data/languages/vu1.slaspec` and the same for `vu0`.

The tests run on the standalone languages by default; `VU_EMBED=VU1` (or `VU0`) runs `ghidis.sh` on the R5900 language with that unit's micro mode instead. Every corpus and emulator test passes both ways.

## Running everything

`runall.sh` runs every check below that needs only the local corpora: each disassembly corpus on the standalone language and inside R5900 (VU1 and VU0), and the emulator tests in all four modes. It ends with `ALL PASSED`, and a language that fails to compile fails the run. The corpora are local and gitignored: `sweep.bin`, `dense.bin` and `rand.bin` come from `sweep.py`, their references and `corpus_<game>.bin` from `refdis.py` and `checkgame.sh`, and `semantics_built.txt` from `mktests.py`.

## Disassembly

| Step | Tool |
|---|---|
| Reference text | `refdis.py RAW OUT` disassembles raw microcode with `dvp-objdump` |
| Ghidra text | `ghidis.sh RAW OUT` disassembles it with the repo's language (`DumpVU.java`) |
| Diff | `compare.py REF GHIDRA` must report every instruction matching |

Corpora:
- `sweep.py sweep.bin` writes instructions for every opcode value with random operand bits, which also covers each instruction's reserved fields (the generator's `RESERVED` table lists them); `sweep.py dense.bin 200` writes a denser one.
- `sweep.py rand.bin random 200000` writes fully random 64-bit words, covering flag bits, invalid halves and unusual sequences.
- `extract_mpg.py ELF DIR` pulls a game's microcode out of `.vutext`. Game microcode is never committed (see `.gitignore`).

`checkgame.sh ELF NAME` runs the whole check for one game: extract, reference disassembly in the PS2SDK container (`CONTAINER`, default `projectryno-svo75`), Ghidra disassembly, compare, then the import with `verify`.

Results on the Ratchet & Clank boot ELFs (every region and version of a game carries the same microcode):

| Game | Builds | Uploads | Instructions match | Microprograms | Functions | Decompile failures |
|---|---|---|---|---|---|---|
| Ratchet & Clank | 4 | 43 | 9,230 / 9,230 | 13 | 78 | 0 |
| Going Commando | 4 | 50 | 10,716 / 10,716 | 14 | 96 | 0 |
| Up Your Arsenal | 3 | 53 | 11,648 / 11,648 | 16 | 104 | 0 |
| Deadlocked | 4 | 62 | 13,232 / 13,232 | 22 | 140 | 0 |

Instruction counts include one trailing nop. Some builds also have `.DVP.overlay..VUADDR.*` sections, one per upload, but they hold zeros: only their names and sizes carry information.

`compare.py` allows only these differences, all because SLEIGH cannot print otherwise: whitespace, the reference's `<symbol+offset>` after branch targets, computed immediates in hex (`iaddiu`, `fs*`), and `loi` showing the raw word (compared through `%g`, as the reference prints it).

## Semantics

`semantics.vut` holds 71 emulator tests in `dvp-as` syntax, covering every instruction, the flags, the branch forms and address wrap. `mktests.py` assembles them, and `EmuVU.java` runs each one in Ghidra's p-code emulator and checks the registers and VU memory it names. EmuVU models the p-code operations the language leaves opaque as the VU manual defines them (`esin` is sin, `eatan` is atan, `eexp` is e^-x) and records `xgkick` addresses.

```
python mktests.py semantics.vut semantics_built.txt     # in the container
python -c "open('blank.bin', 'wb').write(bytes(1024))"   # any small file to import
GHIDIS_SCRIPT=EmuVU.java GHIDIS_ARGS=semantics_built.txt bash ghidis.sh blank.bin result.txt
VU_SLASPEC=vu0.slaspec GHIDIS_SCRIPT=EmuVU.java GHIDIS_ARGS=semantics_built.txt bash ghidis.sh blank.bin result0.txt
```

## Import

In an EE program the "PS2 VU Microcode" analyzer builds the microcode during auto-analysis: each microprogram becomes an overlay (`vu0_mpg_…`, `vu1_mpg_…`) at its VU addresses, decoded in micro mode, and EE code that starts a program gets a reference to it. `GHRUN_ANALYZE=1 ghrun.sh ELF CheckVuInPlace.java -scriptPath vu-tests` imports an ELF with auto-analysis and checks the result: overlays, functions, EE references, decompilation, and functions or flow overrides Ghidra's other analyzers added. Ghidra's Shared Return Calls analyzer turns jumps into code that several VU functions share into tail calls (`CALL_RETURN`) to a function of its own; the extension's MIPS analyzers leave the VU overlays alone.

`ghrun.sh ELF ImportVuMicrocode.java verify` builds the extension, imports an EE ELF, builds the VU code from its `.vutext` (in the program, or with `separate` as programs of their own) and decompiles every function, listing each function and its comment. Options (see the script's header) choose another section (`section:NAME`), an address range (`range:START-END`) or bare microcode (`raw:VUADDR`); use `key:value` here, because Windows batch files split arguments at `=`.

Each upload runs on VU0 or VU1; with `separate` the import makes one program per unit (`_vu0`, `_vu1`). An upload is VU0's when EE code passes its DMA chain to a function that writes the VIF0 DMA channel's registers (`0x10008000`), as Deadlocked's `VU0_loadMicroProgram` does; everything else, and anything too big for VU0's 4 KB, is VU1's. `VU0` or `VU1` forces one unit; `VU0` refuses uploads that do not fit. An upload is known to be VU1's when its run of uploads is too big for VU0 or EE code points at its DMA packet some other way (in code, or through a pointer table in data). When nothing in the program sends it, VU1 is assumed and its block and entry function say so: code that sends it may only be in a level, so a memory dump can tell (in Deadlocked, sarathos's level code sends `mpg_00115b5c` to VU0). VIF0 chains are followed through `cnt` tags, as chain mode runs them; other references cover only the packet they point at.

`ImportVuMicrocode.java replace` removes the VU overlays an earlier import made, with the EE references to them, and imports again. `both` makes the overlays and the separate programs, to view each unit's code on its own too. From the Script Manager the script asks for all of this in one dialog.

The import makes a function at each program entry, after each E bit, at each `bal`/`jalr` target, and at each VU address EE code starts: VIF MSCAL, MSCALF and MSCNT commands, and VU0's `vcallms`. It finds the VIF commands by following constants through each EE function, for example `lui t7,0x1400` / `lui t4,%hi(entry)` / `addiu t4,t4,%lo(entry)` / `sra t4,t4,3` / `or t4,t4,t7`. An entry belongs to the upload the same EE function points at, or else to the one upload that covers the address; otherwise the call is only noted on functions that already start there.

Separate VU programs are marked as analyzed, and `vu.pspec` turns Ghidra's analyzers off by default for them: they assume a stack and calls that return to the next instruction, and on VU code they turned hand-made calls (a `b` whose delay slot sets `vi15`) into calls that return to the wrong place. `AnalyzeVuCheck.java` runs auto-analysis on the imported programs and reports any change (`ghrun.sh ELF ImportVuMicrocode.java -postScript AnalyzeVuCheck.java -scriptPath vu-tests`). Code that branches outside its own upload gets the one other upload that covers the target added to its overlay, as resident code. MPG commands whose data is not microcode (upper words with reserved bits set) are skipped, so other data sections can be searched.

`mkimport.py OUT.elf` (in the container) builds a small EE ELF that exercises these: a branch into a resident upload, an MSCAL tied to an upload, and one that is not.

The decompiler's warnings on game microcode come from the code itself, not from the language:

| Warning | Cause |
|---|---|
| Removing unreachable block | Constant propagation: a register set to a constant on the path from this entry decides a branch, or `max`/`mini` compare a constant (for example a vector derived from vf00) |
| Could not recover jumptable / Treating indirect jump as call | `jr` through a register loaded at run time, a dispatch the decompiler cannot enumerate |
| Instruction at X overlaps instruction at Y | A branch into another branch's delay slot |
| Do nothing block with infinite loop | Spin traps in the game, such as a branch back to an `ibeq` whose register never changes |

## Known limits

- Pipeline timing is not modelled, and p-code cannot model it: every instruction sees the results of all earlier ones. On the VU, FMAC results (and the MAC, status and clip flags they set) appear 4 cycles later, `div`/`sqrt` write Q after 7 cycles and `rsqrt` after 13, EFU results reach P after their own latency, and the pipeline stalls on a register that is still in flight. Code that relies on reading a stale value inside a latency window (common in hand-scheduled loops) decompiles and emulates as if it read the new value.
- Arithmetic sets the MAC flags and status bits exactly from the IEEE result, but the result stays IEEE: where the VU clamps an overflow to +-0x7f7fffff, flushes an underflow to +-0 or gives +-0x7f7fffff for a division by zero, the result here is infinite, denormal or NaN. Exact clamping puts bit tests around every float operation in decompiled code. The VU also treats infinity and NaN operands as ordinary large numbers and denormal operands as zero; IEEE does not.
- A result that underflows so far that IEEE rounds it to zero sets Z but not U.
- EFU transcendentals (`esin`, `eatan`, `eatanxy`, `eatanxz`, `eexp`) and `xgkick` are p-code operations, so the decompiler shows them as calls. Ghidra's own emulator needs a callback for each, as `EmuVU.java` registers.
