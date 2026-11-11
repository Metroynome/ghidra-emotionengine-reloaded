// Disassembles every 8-byte slot of the program and writes `ADDRESS<tab>LOWERHEX UPPERHEX<tab>TEXT`,
// matching vu-tests/refdis.py. The output path is the first script argument.
//@category PS2

import java.io.PrintWriter;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class DumpVU extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String out = getScriptArgs()[0];
		// In the R5900 language, VU microcode decodes where the VUMODE context is 1 (VU0) or 2 (VU1).
		ghidra.program.model.lang.Register vumode = currentProgram.getRegister("VUMODE");
		if (vumode != null) {
			int unit = getScriptArgs().length > 1 && getScriptArgs()[1].equalsIgnoreCase("VU0") ? 1 : 2;
			for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
				if (!block.isInitialized()) {
					continue;
				}
				currentProgram.getProgramContext().setValue(vumode, block.getStart(), block.getEnd(),
					java.math.BigInteger.valueOf(unit));
			}
		}
		try (PrintWriter w = new PrintWriter(out)) {
			for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
				// The R5900 language adds uninitialized blocks for hardware registers.
				if (!block.isInitialized()) {
					continue;
				}
				Address start = block.getStart();
				long size = block.getSize();
				// Linear, not flow-following, so every slot is decoded, including delay slots.
				DisassembleCommand cmd = new DisassembleCommand(start, new AddressSet(start, block.getEnd()), false);
				cmd.applyTo(currentProgram, monitor);
				for (long off = 0; off + 8 <= size; off += 8) {
					Address a = start.add(off);
					// Disassembly stops after an instruction with no fall-through (jr, b, an E-slot
					// end), so restart at each gap and run on, keeping any delay slot in range.
					if (getInstructionAt(a) == null) {
						cmd = new DisassembleCommand(a, new AddressSet(a, block.getEnd()), false);
						cmd.applyTo(currentProgram, monitor);
					}
					Instruction insn = getInstructionAt(a);
					byte[] b = getBytes(a, 8);
					String text = insn == null ? "*unknown*" : insn.toString();
					// Ghidra marks an instruction in a delay slot with a leading underscore.
					if (insn != null && insn.isInDelaySlot() && text.startsWith("_")) {
						text = text.substring(1);
					}
					w.printf("%04x\t%s %s\t%s%n", off, word(b, 0), word(b, 4), text);
				}
			}
		}
	}

	private static String word(byte[] b, int at) {
		StringBuilder s = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			s.append(String.format("%02x", b[at + i] & 0xff));
		}
		return s.toString();
	}
}
