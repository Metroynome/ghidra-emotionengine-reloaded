// Create a VU micro mode program from the microcode in this EE program.
//
// By default the microcode is read from the .vutext section, which holds DMA chains of VIF
// packets. Each VIF MPG command uploads microcode to a VU micro memory address. Uploads that
// continue where the previous one ended form one microprogram; an upload to an address already
// used starts a new one. Each microprogram becomes an overlay at its VU address, so microprograms
// that share VU addresses never collide.
//
// When a microprogram's code flows outside its own upload (into code another upload left resident
// in micro memory) and exactly one other upload covers that address, that upload is added to the
// microprogram's overlay too.
//
// Functions are made at each microprogram's start, after each E bit (the next program usually
// starts there), at bal/jalr targets, and at addresses EE code passes to VIF MSCAL, MSCALF or MSCNT.
// The EE call sites are noted in the function comments.
//
// Script arguments, all optional, in any order (key:value or key=value). Run from the Script
// Manager without arguments, the script asks for them.
//   VU0 | VU1          target unit (default VU1)
//   section:NAME       read microcode from this EE section instead of .vutext
//   range:START-END    read microcode from these EE addresses (hex, END exclusive)
//   raw:VUADDR         the bytes are bare microcode for VU address VUADDR (hex), not VIF packets
//   noentries          do not search EE code for MSCAL entry points
//   verify             decompile every function and print a summary, as the tests do
//   show:FUNCTION      with verify, print that function's C
//@category ghidra-emotionengine

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class ImportVuMicrocode extends GhidraScript {

	private static final int VIF_MPG = 0x4a;
	private static final Map<Integer, String> VIF_CALLS = Map.of(0x14, "MSCAL", 0x15, "MSCALF", 0x17, "MSCNT");

	/** One microprogram: consecutive MPG uploads. */
	private static class Microprogram {
		String name;
		long source;              // EE address of the first MPG command (or of raw code)
		long vuAddress;           // VU micro memory address in bytes
		ByteArrayOutputStream code = new ByteArrayOutputStream();
		AddressSpace space;       // its overlay space in the VU program

		long end() {
			return vuAddress + code.size();
		}
	}

	/** A VIF call EE code builds: the command, its VU address and where the EE builds it. */
	private record EeCall(String command, long vuAddress, Address site, Set<Long> vutextRefs) {
	}

	private int uploads, rejected;
	private long memorySize;

	@Override
	protected void run() throws Exception {
		String unit = "VU1", section = null, show = null;
		Address rangeStart = null, rangeEnd = null;
		Long raw = null;
		boolean verify = false, eeEntries = true;
		String[] args = getScriptArgs();
		if (args.length == 0 && !isRunningHeadless()) {
			args = askString("Import VU microcode",
				"Options: VU0 | VU1, section:NAME, range:START-END, raw:VUADDR, noentries, verify", "VU1").trim()
					.split("\\s+");
		}
		for (String arg : args) {
			// key:value and key=value are the same; Windows batch files split arguments at '='.
			String a = arg.trim().replaceFirst("^(?i)(section|range|raw|show):", "$1=");
			String lower = a.toLowerCase();
			if (lower.equals("vu0") || lower.equals("vu1")) {
				unit = a.toUpperCase();
			}
			else if (lower.equals("verify")) {
				verify = true;
			}
			else if (lower.equals("noentries")) {
				eeEntries = false;
			}
			else if (lower.startsWith("section=")) {
				section = a.substring(8);
			}
			else if (lower.startsWith("range=")) {
				String[] r = a.substring(6).split("-");
				rangeStart = toAddr(Long.decode(hex(r[0])));
				rangeEnd = toAddr(Long.decode(hex(r[1])));
			}
			else if (lower.startsWith("raw=")) {
				raw = Long.decode(hex(a.substring(4)));
			}
			else if (lower.startsWith("show=")) {
				show = a.substring(5);
			}
			else {
				show = a;   // older form: VU1 verify FUNCTION
			}
		}
		memorySize = unit.equals("VU0") ? 0x1000 : 0x4000;

		// The bytes to read.
		Address sourceStart;
		byte[] data;
		if (rangeStart != null) {
			sourceStart = rangeStart;
			data = new byte[(int) (rangeEnd.getOffset() - rangeStart.getOffset())];
		}
		else {
			String blockName = section != null ? section : ".vutext";
			MemoryBlock block = currentProgram.getMemory().getBlock(blockName);
			if (block == null) {
				printerr("This program has no " + blockName + " section. Give section= or range=.");
				return;
			}
			sourceStart = block.getStart();
			data = new byte[(int) block.getSize()];
		}
		currentProgram.getMemory().getBytes(sourceStart, data);

		List<Microprogram> programs;
		if (raw != null) {
			Microprogram mp = new Microprogram();
			mp.source = sourceStart.getOffset();
			mp.vuAddress = raw;
			mp.code.write(data, 0, data.length & ~7);
			mp.name = String.format("raw_%08x", mp.source);
			programs = List.of(mp);
			uploads = 1;
		}
		else {
			programs = parse(data, sourceStart.getOffset());
		}
		if (programs.isEmpty()) {
			printerr("No VIF MPG uploads found.");
			return;
		}
		for (Microprogram mp : programs) {
			if (mp.end() > memorySize) {
				printerr(String.format("%s runs past the end of %s micro memory (0x%x).", mp.name, unit, memorySize));
				return;
			}
		}

		Language language = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("VU:LE:32:" + unit));
		String name = currentProgram.getName() + "_" + unit.toLowerCase();
		Program vu = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
		Memory memory = vu.getMemory();
		int tx = vu.startTransaction("Import VU microcode");
		List<Function> functions = new ArrayList<>();
		int resident = 0, unresolved = 0, eeApplied = 0;
		List<EeCall> calls = List.of();
		try {
			for (Microprogram mp : programs) {
				Address start = vu.getAddressFactory().getDefaultAddressSpace().getAddress(mp.vuAddress);
				byte[] code = mp.code.toByteArray();
				MemoryBlock block = memory.createInitializedBlock(mp.name, start, new ByteArrayInputStream(code),
					code.length, monitor, true);
				block.setExecute(true);
				block.setComment(String.format("%s at %08x in %s", raw != null ? "Microcode" : "VIF MPG upload",
					mp.source, currentProgram.getName()));
				mp.space = block.getStart().getAddressSpace();
				disassemble(vu, mp);
			}

			// Code that flows outside its own upload runs code another upload left in micro memory.
			// Add that upload when only one covers the address.
			for (int round = 0; round < 4; round++) {
				Set<Microprogram> changed = new LinkedHashSet<>();
				for (Microprogram mp : programs) {
					for (long target : escapes(vu, mp)) {
						Microprogram other = residentFor(vu, programs, mp, target);
						if (other == null) {
							continue;
						}
						MemoryBlock b = memory.createInitializedBlock(mp.name + "_" + other.name,
							at(mp, other.vuAddress), new ByteArrayInputStream(other.code.toByteArray()),
							other.code.size(), monitor, false);
						b.setExecute(true);
						b.setComment(String.format("Resident code from the upload at %08x, which %s runs into",
							other.source, mp.name));
						resident++;
						changed.add(mp);
					}
				}
				if (changed.isEmpty()) {
					break;
				}
				for (Microprogram mp : changed) {
					for (ghidra.program.model.address.AddressRange r : spaceSet(memory, mp.space)) {
						vu.getListing().clearCodeUnits(r.getMinAddress(), r.getMaxAddress(), false);
					}
					disassemble(vu, mp);
				}
			}
			for (Microprogram mp : programs) {
				for (long target : escapes(vu, mp)) {
					unresolved++;
					println(String.format("%s flows to 0x%04x, which %s", mp.name, target,
						coveredBy(programs, mp, target).isEmpty() ? "no upload covers"
							: "several uploads cover; none was added"));
				}
			}

			for (Microprogram mp : programs) {
				AddressSet body = spaceSet(memory, mp.space);
				Address entry = at(mp, mp.vuAddress);
				Function f = vu.getFunctionManager().getFunctionAt(entry);
				if (f == null && vu.getListing().getInstructionAt(entry) != null) {
					f = vu.getFunctionManager().createFunction(mp.name, entry, new AddressSet(entry), SourceType.ANALYSIS);
				}
				if (f != null) {
					functions.add(f);
				}
				// A microprogram usually has several entry points, each started by an EE MSCAL and
				// ending at an E bit; the next one normally begins right after that end. The E bit is
				// bit 30 of the upper (second) word, and the instruction after it is the last one run.
				for (Instruction insn : vu.getListing().getInstructions(body, true)) {
					if ((memory.getInt(insn.getAddress().add(4)) & 0x40000000) == 0) {
						continue;
					}
					Address next = insn.getAddress().add(16);
					if (body.contains(next) && vu.getFunctionManager().getFunctionContaining(next) == null
						&& vu.getListing().getInstructionAt(next) != null) {
						functions.add(vu.getFunctionManager().createFunction(
							String.format("%s_%04x", mp.name, next.getOffset()), next, new AddressSet(next),
							SourceType.ANALYSIS));
					}
				}
				// bal and jalr call subroutines that return with jr vi15. Without a function of
				// their own, a subroutine becomes part of each caller's body.
				for (Instruction insn : vu.getListing().getInstructions(body, true)) {
					if (!insn.getFlowType().isCall()) {
						continue;
					}
					for (Address target : insn.getFlows()) {
						if (body.contains(target) && vu.getFunctionManager().getFunctionAt(target) == null
							&& vu.getListing().getInstructionAt(target) != null) {
							functions.add(vu.getFunctionManager().createFunction(
								String.format("%s_sub_%04x", mp.name, target.getOffset()), target,
								new AddressSet(target), SourceType.ANALYSIS));
						}
					}
				}
			}

			if (eeEntries && raw == null) {
				calls = findEeCalls(sourceStart, sourceStart.add(data.length));
				for (EeCall call : calls) {
					eeApplied += applyEeCall(vu, programs, call, functions);
				}
				writeNotes();
			}

			for (Function f : functions) {
				CreateFunctionCmd.fixupFunctionBody(vu, f, monitor);
			}
		}
		finally {
			vu.endTransaction(tx, true);
		}
		println(String.format("%d MPG uploads became %d microprograms in %s", uploads, programs.size(), name));
		if (rejected > 0) {
			println(String.format("Skipped %d MPG-like words whose data is not microcode", rejected));
		}
		println(String.format("Resident uploads added: %d; flows left outside the program: %d", resident, unresolved));
		if (eeEntries && raw == null) {
			println(String.format("EE code builds %d VIF calls with a VU address; %d marked entry points", calls.size(),
				eeApplied));
		}

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
				println("FUNCTION " + f.getName() + " at " + f.getEntryPoint()
					+ (f.getComment() != null ? " // " + f.getComment().replace("\n", " | ") : ""));
				String c = r.getDecompiledFunction().getC();
				if (f.getName().equals(show)) {
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

	/** The address in the program's own overlay, even where the overlay has no block yet. */
	private static Address at(Microprogram mp, long offset) {
		return mp.space instanceof OverlayAddressSpace o ? o.getAddressInThisSpaceOnly(offset) : mp.space.getAddress(offset);
	}

	private static String hex(String s) {
		return s.startsWith("0x") || s.startsWith("0X") ? s : "0x" + s;
	}

	private static AddressSet spaceSet(Memory memory, AddressSpace space) {
		AddressSet set = new AddressSet();
		for (MemoryBlock b : memory.getBlocks()) {
			if (b.getStart().getAddressSpace().equals(space)) {
				set.add(b.getStart(), b.getEnd());
			}
		}
		return set;
	}

	/** Follows flow from the program's start, then decodes whatever is left linearly. */
	private void disassemble(Program vu, Microprogram mp) {
		AddressSet body = spaceSet(vu.getMemory(), mp.space);
		Address entry = at(mp, mp.vuAddress);
		new DisassembleCommand(entry, body, true).applyTo(vu, monitor);
		for (Address a : body.getAddresses(true)) {
			if (a.getOffset() % 8 == 0 && vu.getListing().getCodeUnitContaining(a) != null
				&& vu.getListing().getInstructionContaining(a) == null) {
				new DisassembleCommand(a, body, false).applyTo(vu, monitor);
			}
		}
	}

	/**
	 * VU addresses the program's branches and calls go to that are not in its overlay. Falling off
	 * the end is not counted: uploads often end in padding that is never run.
	 */
	private Set<Long> escapes(Program vu, Microprogram mp) {
		AddressSet body = spaceSet(vu.getMemory(), mp.space);
		Set<Long> out = new TreeSet<>();
		for (Instruction insn : vu.getListing().getInstructions(body, true)) {
			for (Address t : insn.getFlows()) {
				Address inSpace = at(mp, t.getOffset());
				if (!body.contains(inSpace)) {
					out.add(t.getOffset());
				}
			}
		}
		return out;
	}

	private static List<Microprogram> coveredBy(List<Microprogram> programs, Microprogram mp, long target) {
		List<Microprogram> out = new ArrayList<>();
		for (Microprogram q : programs) {
			if (q != mp && q.vuAddress <= target && target < q.end()) {
				out.add(q);
			}
		}
		return out;
	}

	/** The one upload that covers target and fits beside what the program's overlay holds. */
	private Microprogram residentFor(Program vu, List<Microprogram> programs, Microprogram mp, long target) {
		AddressSet body = spaceSet(vu.getMemory(), mp.space);
		Microprogram found = null;
		for (Microprogram q : coveredBy(programs, mp, target)) {
			if (body.intersects(at(mp, q.vuAddress), at(mp, q.end() - 1))) {
				continue;
			}
			if (found != null && !Arrays.equals(found.code.toByteArray(), q.code.toByteArray())) {
				return null;
			}
			found = found == null ? q : found;
		}
		return found;
	}

	/** Walks the VIF stream for MPG commands, grouping uploads that continue one another. */
	private List<Microprogram> parse(byte[] data, long base) {
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
				if (i + 4 + length > data.length || address + length > memorySize || !isMicrocode(data, i + 4, num)) {
					rejected++;
					i += 4;
					continue;
				}
				if (current == null || address != current.end()) {
					current = new Microprogram();
					current.source = base + i;
					current.vuAddress = address;
					current.name = String.format("mpg_%08x", current.source);
					programs.add(current);
				}
				current.code.write(data, i + 4, length);
				uploads++;
				i += 4 + length;
			}
			else {
				i += 4;
			}
		}
		return programs;
	}

	/**
	 * Whether MPG data looks like microcode: bits 25 and 26 of every upper word are zero, as no upper
	 * instruction sets them. This keeps a stray 0x4a byte in other data from becoming an upload.
	 */
	private static boolean isMicrocode(byte[] data, int at, int count) {
		for (int k = 0; k < count; k++) {
			if ((word(data, at + 8 * k + 4) & 0x06000000) != 0) {
				return false;
			}
		}
		return true;
	}

	private static int word(byte[] b, int at) {
		return (b[at] & 0xff) | (b[at + 1] & 0xff) << 8 | (b[at + 2] & 0xff) << 16 | (b[at + 3] & 0xff) << 24;
	}

	// ---- VIF calls built by EE code ----

	/**
	 * Finds VIF MSCAL, MSCALF and MSCNT commands that EE code builds with a constant VU address, for
	 * example lui t7,0x1400 / lui t4,%hi(entry) / addiu t4,t4,%lo(entry) / sra t4,t4,3 / or t4,t4,t7.
	 * Each function (code between jr ra returns) is scanned once, tracking registers that hold
	 * constants. The function's references into the microcode source say which upload it uses.
	 */
	private List<EeCall> findEeCalls(Address sourceStart, Address sourceEnd) throws Exception {
		List<EeCall> out = new ArrayList<>();
		if (!currentProgram.getLanguage().getProcessor().toString().toLowerCase().contains("mips")
			&& !currentProgram.getLanguage().getLanguageID().toString().toLowerCase().contains("r5900")) {
			return out;
		}
		long srcLo = sourceStart.getOffset(), srcHi = sourceEnd.getOffset();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			// A raw memory dump is one block holding both the microcode and the EE code, so only
			// the microcode's own words are left out, not the whole block.
			if (!block.isExecute() || !block.isInitialized() || !block.getStart().getAddressSpace().isMemorySpace()) {
				continue;
			}
			long base = block.getStart().getOffset();
			int n = (int) (block.getSize() / 4);
			int[] ins = new int[n];
			byte[] bytes = new byte[n * 4];
			block.getBytes(block.getStart(), bytes);
			for (int k = 0; k < n; k++) {
				ins[k] = word(bytes, 4 * k);
			}
			int f0 = 0;
			for (int k = 0; k <= n; k++) {
				boolean inSource = k < n && base + 4L * k >= srcLo && base + 4L * k < srcHi;
				boolean wasSource = k > 0 && base + 4L * (k - 1) >= srcLo && base + 4L * (k - 1) < srcHi;
				// A function ends after jr ra and its delay slot, and at either edge of the microcode.
				boolean end = k == n || (k >= 2 && ins[k - 2] == 0x03e00008) || inSource != wasSource;
				if (end && k > f0) {
					if (!wasSource) {
						scanFunction(block, ins, f0, k, srcLo, srcHi, out);
					}
					f0 = k;
				}
			}
		}
		return out;
	}

	private void scanFunction(MemoryBlock block, int[] ins, int from, int to, long srcLo, long srcHi,
			List<EeCall> out) {
		Map<Integer, Long> regs = new HashMap<>();
		Map<Integer, Long> hi = new HashMap<>();
		Set<Long> refs = new TreeSet<>();
		List<long[]> found = new ArrayList<>();
		regs.put(0, 0L);
		int clobberAt = -1;
		for (int m = from; m < to; m++) {
			if (m == clobberAt) {
				// A call clobbers the temporaries and ra once its delay slot has run; s0-s7, sp and fp
				// survive it.
				for (int r : new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 31 }) {
					regs.remove(r);
					hi.remove(r);
				}
			}
			int x = ins[m];
			int op = x >>> 26, rs = (x >>> 21) & 31, rt = (x >>> 16) & 31, rd = (x >>> 11) & 31, sa = (x >>> 6) & 31;
			int fn = x & 63, imm = x & 0xffff;
			long simm = (short) imm;
			Integer dst = null;
			Long val = null;
			// Loads and stores at %lo(x)(base) with base = %hi(x).
			if ((op >= 0x20 && op <= 0x2f || op == 0x37 || op == 0x3f || op == 0x1e || op == 0x1f) && hi.containsKey(rs)) {
				long v = (hi.get(rs) + simm) & 0xffffffffL;
				if (v >= srcLo && v < srcHi) {
					refs.add(v);
				}
			}
			if (op == 0x0f) {                                     // lui
				dst = rt;
				val = (long) imm << 16;
				hi.put(rt, val);
			}
			else if (op == 0x08 || op == 0x09 || op == 0x18 || op == 0x19) {   // addi addiu daddi daddiu
				dst = rt;
				val = regs.containsKey(rs) ? (regs.get(rs) + simm) & 0xffffffffL : null;
				if (hi.containsKey(rs)) {
					long v = (hi.get(rs) + simm) & 0xffffffffL;
					if (v >= srcLo && v < srcHi) {
						refs.add(v);
					}
				}
			}
			else if (op == 0x0d) {                                // ori
				dst = rt;
				val = regs.containsKey(rs) ? regs.get(rs) | imm : null;
				if (hi.containsKey(rs)) {
					long v = hi.get(rs) | imm;
					if (v >= srcLo && v < srcHi) {
						refs.add(v);
					}
				}
			}
			else if (op == 0 && (fn == 0x25 || fn == 0x21 || fn == 0x2d)) {   // or addu daddu
				dst = rd;
				if (regs.containsKey(rs) && regs.containsKey(rt)) {
					val = fn == 0x25 ? regs.get(rs) | regs.get(rt) : (regs.get(rs) + regs.get(rt)) & 0xffffffffL;
				}
			}
			else if (op == 0 && (fn == 0x02 || fn == 0x03)) {    // srl sra
				dst = rd;
				val = regs.containsKey(rt) ? regs.get(rt) >>> sa : null;
			}
			else if (op == 0 && fn == 0x00 && x != 0) {           // sll
				dst = rd;
				val = regs.containsKey(rt) ? (regs.get(rt) << sa) & 0xffffffffL : null;
			}
			else if (op == 0 && fn != 0x08 && fn != 0x09 && fn != 0x0c && fn != 0x0d && fn != 0x0f) {
				dst = rd;                                         // any other ALU op: unknown result
			}
			else if (op >= 0x20 && op <= 0x27 || op == 0x37 || op == 0x1e || op == 0x0c || op == 0x0e
				|| op == 0x0a || op == 0x0b || op == 0x1a || op == 0x1b || op == 0x10 || op == 0x12) {
				dst = rt;                                         // loads, andi, xori, slti, coprocessor moves
			}
			else if (op == 0x1c) {
				dst = rd;                                         // MMI
			}
			else if (op == 0x03 || op == 0 && fn == 0x09) {
				clobberAt = m + 2;                                // jal, jalr: after the delay slot
				continue;
			}
			if (dst == null || dst == 0) {
				continue;
			}
			hi.remove(dst);
			if (op == 0x0f) {
				hi.put(dst, val);
			}
			if (val == null) {
				regs.remove(dst);
				continue;
			}
			regs.put(dst, val);
			int cmd = (int) ((val >>> 24) & 0x7f);
			if (VIF_CALLS.containsKey(cmd) && ((val >>> 16) & 0xff) == 0 && (val & 0xffff) != 0) {
				found.add(new long[] { cmd, (val & 0xffff) * 8, m });
			}
		}
		for (long[] f : found) {
			out.add(new EeCall(VIF_CALLS.get((int) f[0]), f[1], block.getStart().add(4 * f[2]), refs));
		}
	}

	/**
	 * Marks the entry point an EE VIF call starts. When the EE function also points at an upload,
	 * the entry belongs to that microprogram and gets a function if it has none. Otherwise only
	 * microprograms that already have a function at that address are noted.
	 */
	private int applyEeCall(Program vu, List<Microprogram> programs, EeCall call, List<Function> functions)
			throws Exception {
		List<Microprogram> named = new ArrayList<>();
		for (Microprogram mp : programs) {
			for (long ref : call.vutextRefs()) {
				if (mp.source >= ref && mp.source < ref + 0x100) {
					named.add(mp);
				}
			}
		}
		int applied = 0;
		for (Microprogram mp : named.isEmpty() ? programs : named) {
			Address a = at(mp, call.vuAddress() % memorySize);
			if (vu.getListing().getInstructionAt(a) == null) {
				continue;
			}
			Function f = vu.getFunctionManager().getFunctionAt(a);
			if (f == null && !named.isEmpty()) {
				f = vu.getFunctionManager().createFunction(String.format("%s_%04x", mp.name, a.getOffset()), a,
					new AddressSet(a), SourceType.ANALYSIS);
				functions.add(f);
			}
			if (f == null) {
				continue;
			}
			String key = named.isEmpty() ? "May be started by " + call.command() + " at EE"
				: "Started by " + call.command() + " at EE";
			notes.computeIfAbsent(f, k -> new java.util.TreeMap<>()).computeIfAbsent(key, k -> new TreeSet<>())
					.add(call.site().toString());
			applied++;
		}
		return applied;
	}

	/** EE call sites per function, grouped by note. */
	private final Map<Function, Map<String, Set<String>>> notes = new HashMap<>();

	private void writeNotes() {
		for (Map.Entry<Function, Map<String, Set<String>>> e : notes.entrySet()) {
			List<String> lines = new ArrayList<>();
			for (Map.Entry<String, Set<String>> n : e.getValue().entrySet()) {
				lines.add(n.getKey() + " " + String.join(", ", n.getValue())
					+ (n.getKey().startsWith("May") ? " (that code does not say which upload is resident)" : ""));
			}
			e.getKey().setComment(String.join("\n", lines));
		}
	}
}
