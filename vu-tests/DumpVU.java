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
		try (PrintWriter w = new PrintWriter(out)) {
			for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
				Address start = block.getStart();
				long size = block.getSize();
				for (long off = 0; off + 8 <= size; off += 8) {
					Address a = start.add(off);
					if (getInstructionAt(a) == null) {
						DisassembleCommand cmd = new DisassembleCommand(a, new AddressSet(a, a.add(7)), false);
						cmd.applyTo(currentProgram, monitor);
					}
					Instruction insn = getInstructionAt(a);
					byte[] b = getBytes(a, 8);
					String text = insn == null ? "*unknown*" : insn.toString();
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
