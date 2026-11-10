// Decompiles VU microcode and reports failures. Script arguments: output path, then the byte
// offsets where programs start. Each start becomes a function; the first one's C is written in full.
//@category PS2

import java.io.PrintWriter;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class DecompVU extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		MemoryBlock block = currentProgram.getMemory().getBlocks()[0];
		Address base = block.getStart();
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		int ok = 0, failed = 0, warned = 0;
		try (PrintWriter w = new PrintWriter(args[0])) {
			for (int k = 1; k < args.length; k++) {
				Address entry = base.add(Long.decode(args[k]));
				if (getInstructionAt(entry) == null) {
					new DisassembleCommand(entry, null, true).applyTo(currentProgram, monitor);
				}
				Function f = getFunctionAt(entry);
				if (f == null) {
					f = createFunction(entry, String.format("vu_%05x", Long.decode(args[k])));
				}
				if (f == null) {
					w.printf("%s: no function%n", entry);
					failed++;
					continue;
				}
				DecompileResults r = decomp.decompileFunction(f, 60, monitor);
				if (!r.decompileCompleted() || r.getDecompiledFunction() == null) {
					w.printf("%s: FAILED %s%n", f.getName(), r.getErrorMessage());
					failed++;
					continue;
				}
				String c = r.getDecompiledFunction().getC();
				String msg = r.getErrorMessage();
				boolean warn = c.contains("WARNING") || (msg != null && !msg.isEmpty());
				if (warn) {
					warned++;
					for (String line : c.split("\n")) {
						if (line.contains("WARNING")) {
							w.printf("%s: %s%n", f.getName(), line.trim());
						}
					}
				}
				ok++;
				if (k == 1) {
					w.println(c);
				}
			}
			w.printf("decompiled %d, warnings in %d, failed %d%n", ok, warned, failed);
		}
		decomp.dispose();
	}
}
