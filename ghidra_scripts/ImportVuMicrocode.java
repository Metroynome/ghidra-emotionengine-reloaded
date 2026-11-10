// Create a VU micro mode program from the microcode in this EE program's .vutext section.
//
// .vutext holds DMA/VIF packets. Each VIF MPG command uploads microcode to a VU micro memory
// address. Uploads that continue where the previous one ended form one microprogram; an upload to
// an address already used starts a new one. Each microprogram becomes an overlay block at its VU
// address, so overlays never collide, and is disassembled with a function at its first instruction.
//
// Script arguments (all optional): VU0 or VU1 (default VU1), then "verify" to decompile every
// function and print a summary, as the tests do.
//@category ghidra-emotionengine

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class ImportVuMicrocode extends GhidraScript {

	private static final int VIF_MPG = 0x4a;

	/** One microprogram: consecutive MPG uploads. */
	private static class Microprogram {
		long sourceOffset;        // offset in .vutext of the first MPG command
		long vuAddress;           // VU micro memory address in bytes
		java.io.ByteArrayOutputStream code = new java.io.ByteArrayOutputStream();

		long end() {
			return vuAddress + code.size();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String unit = args.length > 0 && args[0].equalsIgnoreCase("VU0") ? "VU0" : "VU1";
		boolean verify = args.length > 1 && args[1].equalsIgnoreCase("verify");

		MemoryBlock vutext = currentProgram.getMemory().getBlock(".vutext");
		if (vutext == null) {
			printerr("This program has no .vutext section.");
			return;
		}
		byte[] data = new byte[(int) vutext.getSize()];
		vutext.getBytes(vutext.getStart(), data);
		List<Microprogram> programs = parse(data);
		if (programs.isEmpty()) {
			printerr("No VIF MPG uploads found in .vutext.");
			return;
		}

		Language language = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("VU:LE:32:" + unit));
		String name = currentProgram.getName() + "_" + unit.toLowerCase();
		Program vu = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
		int tx = vu.startTransaction("Import VU microcode");
		List<Function> functions = new ArrayList<>();
		try {
			Address vutextBase = vutext.getStart();
			for (Microprogram mp : programs) {
				String blockName = String.format("mpg_%08x", vutextBase.add(mp.sourceOffset).getOffset());
				Address start = vu.getAddressFactory().getDefaultAddressSpace().getAddress(mp.vuAddress);
				byte[] code = mp.code.toByteArray();
				MemoryBlock block = vu.getMemory().createInitializedBlock(blockName, start,
						new ByteArrayInputStream(code), code.length, monitor, true);
				block.setExecute(true);
				block.setComment(String.format("VIF MPG upload at %s in %s", vutextBase.add(mp.sourceOffset),
						currentProgram.getName()));
				Address entry = block.getStart();
				// Follow flow from the entry, then decode whatever is left linearly.
				new DisassembleCommand(entry, new AddressSet(entry, block.getEnd()), true).applyTo(vu, monitor);
				for (Address a = entry; a.compareTo(block.getEnd()) < 0; a = a.add(8)) {
					if (vu.getListing().getInstructionAt(a) == null && vu.getListing().getInstructionContaining(a) == null) {
						new DisassembleCommand(a, new AddressSet(a, block.getEnd()), false).applyTo(vu, monitor);
					}
				}
				Function f = vu.getFunctionManager().getFunctionAt(entry);
				if (f == null) {
					f = vu.getFunctionManager().createFunction(blockName, entry, new AddressSet(entry, entry),
							SourceType.ANALYSIS);
				}
				functions.add(f);
				// A microprogram usually has several entry points, each started by an EE MSCAL and
				// ending at an E bit; the next one normally begins right after that end. The E bit is
				// bit 30 of the upper (second) word, and the instruction after it is the last one run.
				for (Address a = entry; a.add(16).compareTo(block.getEnd()) < 0; a = a.add(8)) {
					int upper = vu.getMemory().getInt(a.add(4));
					if ((upper & 0x40000000) == 0) {
						continue;
					}
					Address next = a.add(16);
					if (vu.getFunctionManager().getFunctionContaining(next) == null
						&& vu.getListing().getInstructionAt(next) != null) {
						Function g = vu.getFunctionManager().createFunction(
							String.format("%s_%04x", blockName, next.getOffset()), next,
							new AddressSet(next, next), SourceType.ANALYSIS);
						functions.add(g);
					}
				}
			}
			for (Function f : functions) {
				ghidra.app.cmd.function.CreateFunctionCmd.fixupFunctionBody(vu, f, monitor);
			}
		}
		finally {
			vu.endTransaction(tx, true);
		}
		println(String.format("%d MPG uploads became %d microprograms in %s", countUploads, programs.size(), name));

		if (verify) {
			DecompInterface decomp = new DecompInterface();
			decomp.openProgram(vu);
			int ok = 0, failed = 0, warned = 0;
			for (Function f : functions) {
				DecompileResults r = decomp.decompileFunction(f, 60, monitor);
				if (!r.decompileCompleted() || r.getDecompiledFunction() == null) {
					println("FAILED " + f.getName() + ": " + r.getErrorMessage());
					failed++;
					continue;
				}
				ok++;
				String c = r.getDecompiledFunction().getC();
				if (args.length > 2 && f.getName().equals(args[2])) {
					println("C of " + f.getName() + ":\n" + c);
				}
				for (String line : c.split("\n")) {
					if (line.contains("WARNING")) {
						println("WARNING " + f.getName() + ": " + line.trim());
						warned++;
					}
				}
			}
			decomp.dispose();
			println(String.format("VERIFY decompiled %d, failed %d, warning lines %d", ok, failed, warned));
		}

		if (getState().getProject() != null) {
			getState().getProject().getProjectData().getRootFolder().createFile(name, vu, monitor);
			println("Saved " + name + " to the project.");
		}
		vu.release(this);
	}

	private int countUploads;

	/** Walks the VIF stream for MPG commands, grouping uploads that continue one another. */
	private List<Microprogram> parse(byte[] data) {
		List<Microprogram> programs = new ArrayList<>();
		Microprogram current = null;
		int i = 0;
		while (i + 4 <= data.length) {
			int code = word(data, i);
			int cmd = (code >>> 24) & 0x7f;
			// MPG data always starts on a 64-bit boundary.
			if (cmd == VIF_MPG && (i + 4) % 8 == 0) {
				int num = (code >>> 16) & 0xff;
				if (num == 0) {
					num = 256;
				}
				long address = (code & 0xffffL) * 8;
				int length = num * 8;
				if (i + 4 + length > data.length) {
					break;
				}
				if (current == null || address != current.end()) {
					current = new Microprogram();
					current.sourceOffset = i;
					current.vuAddress = address;
					programs.add(current);
				}
				current.code.write(data, i + 4, length);
				countUploads++;
				i += 4 + length;
			}
			else {
				i += 4;
			}
		}
		return programs;
	}

	private static int word(byte[] b, int at) {
		return (b[at] & 0xff) | (b[at + 1] & 0xff) << 8 | (b[at + 2] & 0xff) << 16 | (b[at + 3] & 0xff) << 24;
	}
}
