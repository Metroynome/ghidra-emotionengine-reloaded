// Create VU micro mode programs from the microcode in this EE program.
//
// By default the microcode is read from the .vutext section, which holds DMA chains of VIF
// packets. Each VIF MPG command uploads microcode to a VU micro memory address. Uploads that
// continue where the previous one ended form one microprogram; an upload to an address already
// used starts a new one. Each microprogram becomes an overlay at its VU address, so microprograms
// that share VU addresses never collide.
//
// Each upload runs on VU0 or VU1. By default (unit auto) an upload belongs to VU0 when EE code
// hands its DMA chain to a function that writes the VIF0 DMA channel's registers (0x10008000);
// everything else, and anything too big for VU0's 4 KB of micro memory, belongs to VU1. One
// program is made per unit that has uploads, named after this program with _vu0 or _vu1.
//
// When a microprogram's code flows outside its own upload (into code another upload left resident
// in micro memory) and exactly one other upload covers that address, that upload is added to the
// microprogram's overlay too.
//
// Functions are made at each microprogram's start, after each E bit (the next program usually
// starts there), at bal/jalr targets, and at addresses EE code starts: VIF MSCAL, MSCALF and MSCNT
// commands it builds, and VU0's vcallms. The EE call sites are noted in the function comments.
// The new programs are marked as analyzed: Ghidra's auto-analysis knows nothing of VU code (it
// turns hand-made calls, a b whose delay slot sets vi15, into calls that return to the wrong place).
//
// Script arguments, all optional, in any order (key:value or key=value). Run from the Script
// Manager without arguments, the script asks for them.
//   auto | VU0 | VU1   which unit the uploads run on (default auto; VU0 or VU1 puts all on one)
//   section:NAME       read microcode from this EE section instead of .vutext
//   range:START-END    read microcode from these EE addresses (hex, END exclusive)
//   raw:VUADDR         the bytes are bare microcode for VU address VUADDR (hex), not VIF packets
//   noentries          do not mark entry points that EE code starts
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
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
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
import ghidra.program.util.GhidraProgramUtilities;

public class ImportVuMicrocode extends GhidraScript {

	private static final int VIF_MPG = 0x4a;
	private static final Map<Integer, String> VIF_CALLS = Map.of(0x14, "MSCAL", 0x15, "MSCALF", 0x17, "MSCNT");
	private static final Map<String, Long> MEMORY_SIZE = Map.of("VU0", 0x1000L, "VU1", 0x4000L);

	/** One MPG upload. */
	private static class Upload {
		long source;              // EE address of the MPG command
		long vuAddress;           // VU micro memory address in bytes
		byte[] code;
		String unit;
	}

	/** One microprogram: consecutive uploads to consecutive addresses on one unit. */
	private static class Microprogram {
		String name;
		String unit;
		long source;              // EE address of the first MPG command (or of raw code)
		long vuAddress;
		ByteArrayOutputStream code = new ByteArrayOutputStream();
		AddressSpace space;       // its overlay space in its VU program

		long end() {
			return vuAddress + code.size();
		}
	}

	/**
	 * A VU program start EE code makes: the command, the VU address, where the EE code is, the
	 * microcode addresses the same EE function points at, and the unit if the command says (vcallms
	 * is VU0's; a VIF command could be for either VIF).
	 */
	private record EeCall(String command, long vuAddress, Address site, Set<Long> vutextRefs, String unit) {
	}

	private int uploads, rejected;
	private final List<EeCall> eeCalls = new ArrayList<>();
	private final Set<Long> vu0Chains = new TreeSet<>();
	private final List<long[]> vif0Senders = new ArrayList<>();

	@Override
	protected void run() throws Exception {
		String mode = "AUTO", section = null, show = null;
		Address rangeStart = null, rangeEnd = null;
		Long raw = null;
		boolean verify = false, eeEntries = true;
		String[] args = getScriptArgs();
		if (args.length == 0 && !isRunningHeadless()) {
			args = askString("Import VU microcode",
				"Options: auto | VU0 | VU1, section:NAME, range:START-END, raw:VUADDR, noentries, verify", "auto").trim()
					.split("\\s+");
		}
		for (String arg : args) {
			// key:value and key=value are the same; Windows batch files split arguments at '='.
			String a = arg.trim().replaceFirst("^(?i)(section|range|raw|show):", "$1=");
			String lower = a.toLowerCase();
			if (lower.isEmpty()) {
				continue;
			}
			if (lower.equals("vu0") || lower.equals("vu1") || lower.equals("auto")) {
				mode = a.toUpperCase();
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
		long srcLo = sourceStart.getOffset(), srcHi = srcLo + data.length;

		List<Upload> found;
		if (raw != null) {
			Upload u = new Upload();
			u.source = srcLo;
			u.vuAddress = raw;
			u.code = Arrays.copyOf(data, data.length & ~7);
			found = List.of(u);
			uploads = 1;
		}
		else {
			found = parse(data, srcLo);
		}
		if (found.isEmpty()) {
			printerr("No VIF MPG uploads found.");
			return;
		}

		// EE code says which uploads are VU0's and where programs start.
		if ((eeEntries || mode.equals("AUTO")) && raw == null) {
			scanEe(srcLo, srcHi);
		}
		List<String> tooBig = new ArrayList<>();
		for (Upload u : found) {
			u.unit = !mode.equals("AUTO") ? mode : raw == null && inVu0Chain(u) ? "VU0" : "VU1";
			if (u.unit.equals("VU0") && u.vuAddress + u.code.length > MEMORY_SIZE.get("VU0")) {
				if (mode.equals("VU0")) {
					tooBig.add(String.format("%08x (VU 0x%04x-0x%04x)", u.source, u.vuAddress, u.vuAddress + u.code.length));
				}
				else {
					println(String.format("The upload at %08x is too big for VU0, so it is VU1's", u.source));
					u.unit = "VU1";
				}
			}
		}
		if (!tooBig.isEmpty()) {
			printerr(String.format("%d uploads do not fit in VU0's 4 KB of micro memory, so they are not VU0 code: %s. "
				+ "Use auto or VU1.", tooBig.size(), String.join(", ", tooBig)));
			return;
		}

		List<Microprogram> all = group(found, raw != null);
		println(String.format("%d MPG uploads became %d microprograms", uploads, all.size()));
		if (rejected > 0) {
			println(String.format("Skipped %d MPG-like words whose data is not microcode", rejected));
		}
		if (mode.equals("AUTO") && raw == null) {
			println(String.format("VU0: %d chains sent through VIF0 by %d EE functions", vu0Chains.size(),
				vif0Senders.size()));
			for (long chain : vu0Chains) {
				println(String.format("VU0 chain %08x-%08x", chain, chainEnd(chain)));
			}
		}
		for (String unit : List.of("VU0", "VU1")) {
			List<Microprogram> programs = new ArrayList<>();
			for (Microprogram mp : all) {
				if (mp.unit.equals(unit)) {
					programs.add(mp);
				}
			}
			if (!programs.isEmpty()) {
				importUnit(unit, programs, all, eeEntries && raw == null, verify, show);
			}
		}
	}

	/** Builds, checks and saves the program for one unit. */
	private void importUnit(String unit, List<Microprogram> programs, List<Microprogram> all, boolean eeEntries,
			boolean verify, String show) throws Exception {
		Language language = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("VU:LE:32:" + unit));
		String name = currentProgram.getName() + "_" + unit.toLowerCase();
		Program vu = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
		Memory memory = vu.getMemory();
		int tx = vu.startTransaction("Import VU microcode");
		List<Function> functions = new ArrayList<>();
		Map<Function, Map<String, Set<String>>> notes = new HashMap<>();
		int resident = 0, unresolved = 0, eeApplied = 0, eeUsed = 0;
		try {
			for (Microprogram mp : programs) {
				Address start = vu.getAddressFactory().getDefaultAddressSpace().getAddress(mp.vuAddress);
				byte[] code = mp.code.toByteArray();
				MemoryBlock block = memory.createInitializedBlock(mp.name, start, new ByteArrayInputStream(code),
					code.length, monitor, true);
				block.setExecute(true);
				block.setComment(String.format("%s at %08x in %s", mp.name.startsWith("raw") ? "Microcode"
					: "VIF MPG upload", mp.source, currentProgram.getName()));
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
					for (AddressRange r : spaceSet(memory, mp.space)) {
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
				// A microprogram usually has several entry points, each started by the EE and ending at
				// an E bit; the next one normally begins right after that end. The E bit is bit 30 of
				// the upper (second) word, and the instruction after it is the last one run.
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

			if (eeEntries) {
				for (EeCall call : eeCalls) {
					int n = applyEeCall(vu, unit, programs, all, call, functions, notes);
					eeApplied += n;
					eeUsed += n > 0 ? 1 : 0;
				}
				writeNotes(notes);
			}

			for (Function f : functions) {
				CreateFunctionCmd.fixupFunctionBody(vu, f, monitor);
			}
			GhidraProgramUtilities.markProgramAnalyzed(vu);
		}
		finally {
			vu.endTransaction(tx, true);
		}
		println(String.format("%s: %d microprograms in %s", unit, programs.size(), name));
		println(String.format("%s: resident uploads added: %d; flows left outside the program: %d", unit, resident,
			unresolved));
		if (eeEntries) {
			println(String.format("%s: %d EE program starts apply; %d marked entry points", unit, eeUsed, eeApplied));
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
				println("FUNCTION " + unit + " " + f.getName() + " at " + f.getEntryPoint()
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
			println(String.format("VERIFY %s decompiled %d, failed %d, warning lines %d", unit, ok, failed, warned));
		}

		if (getState().getProject() != null) {
			// Save next to the EE program, under a free name.
			DomainFolder folder = currentProgram.getDomainFile() != null
				&& currentProgram.getDomainFile().getParent() != null ? currentProgram.getDomainFile().getParent()
					: getState().getProject().getProjectData().getRootFolder();
			String fileName = name;
			for (int k = 2; folder.getFile(fileName) != null; k++) {
				fileName = name + "_" + k;
			}
			DomainFile saved = folder.createFile(fileName, vu, monitor);
			println("Saved " + saved.getPathname() + " to the project.");
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

	/** Walks the VIF stream for MPG commands. */
	private List<Upload> parse(byte[] data, long base) {
		List<Upload> out = new ArrayList<>();
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
				if (i + 4 + length > data.length || address + length > MEMORY_SIZE.get("VU1")
					|| !isMicrocode(data, i + 4, num)) {
					rejected++;
					i += 4;
					continue;
				}
				Upload u = new Upload();
				u.source = base + i;
				u.vuAddress = address;
				u.code = Arrays.copyOfRange(data, i + 4, i + 4 + length);
				out.add(u);
				uploads++;
				i += 4 + length;
			}
			else {
				i += 4;
			}
		}
		return out;
	}

	/** Groups uploads that follow one another, on one unit and to consecutive addresses. */
	private static List<Microprogram> group(List<Upload> found, boolean raw) {
		List<Microprogram> out = new ArrayList<>();
		Microprogram current = null;
		for (Upload u : found) {
			if (current == null || !current.unit.equals(u.unit) || u.vuAddress != current.end()) {
				current = new Microprogram();
				current.unit = u.unit;
				current.source = u.source;
				current.vuAddress = u.vuAddress;
				current.name = String.format(raw ? "raw_%08x" : "mpg_%08x", u.source);
				out.add(current);
			}
			current.code.write(u.code, 0, u.code.length);
		}
		return out;
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

	// ---- DMA chains ----

	/**
	 * The end of the DMA chain that starts at ref: cnt tags (id 1) continue to the next tag, an end
	 * tag (id 7) ends after its data. Each tag is 16 bytes followed by QWC quadwords. If ref is not a
	 * tag, the chain is taken to be the 256 bytes from ref.
	 */
	private long chainEnd(long ref) {
		long pos = ref;
		try {
			for (int k = 0; k < 4096; k++) {
				int tag = currentProgram.getMemory().getInt(toAddr(pos));
				int qwc = tag & 0xffff, id = (tag >>> 28) & 7;
				long next = pos + 16 + 16L * qwc;
				if (id == 7) {
					return next;
				}
				if (id != 1) {
					break;
				}
				pos = next;
			}
		}
		catch (Exception e) {
			// not readable as a tag
		}
		return pos > ref ? pos : ref + 0x100;
	}

	private boolean inVu0Chain(Upload u) {
		for (long ref : vu0Chains) {
			if (u.source >= ref && u.source < chainEnd(ref)) {
				return true;
			}
		}
		return false;
	}

	// ---- EE code ----

	/** Whether the target address runs EE code; only MIPS programs are scanned. */
	private boolean isEe() {
		return currentProgram.getLanguage().getProcessor().toString().toLowerCase().contains("mips")
			|| currentProgram.getLanguage().getLanguageID().toString().toLowerCase().contains("r5900");
	}

	/** One stretch of EE code between jr ra returns, in a block's word array. */
	private interface FunctionVisitor {
		void visit(MemoryBlock block, int[] ins, int from, int to);
	}

	/**
	 * Calls the visitor for each function in the executable blocks: code between jr ra returns,
	 * leaving out the microcode's own words. A raw memory dump is one block holding both the
	 * microcode and the EE code, so only the microcode is left out, not the whole block.
	 */
	private void forEachFunction(long srcLo, long srcHi, FunctionVisitor visitor) throws Exception {
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
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
						visitor.visit(block, ins, f0, k);
					}
					f0 = k;
				}
			}
		}
	}

	/**
	 * Scans EE code twice. First for functions that send DMA through VIF0: they build an address of
	 * the VIF0 channel's registers, 0x10008000-0x100083ff. Then each function, tracking constants:
	 * VIF MSCAL, MSCALF and MSCNT commands built with a VU address (for example lui t7,0x1400 /
	 * lui t4,%hi(entry) / addiu t4,t4,%lo(entry) / sra t4,t4,3 / or t4,t4,t7), vcallms, and the
	 * microcode chains passed in a0 to a VIF0 sender, which are VU0's.
	 */
	private void scanEe(long srcLo, long srcHi) throws Exception {
		if (!isEe()) {
			return;
		}
		forEachFunction(srcLo, srcHi, (block, ins, from, to) -> {
			if (buildsVif0Address(ins, from, to)) {
				long base = block.getStart().getOffset();
				vif0Senders.add(new long[] { base + 4L * from, base + 4L * to });
				// A sender that names a chain itself sends that chain.
				vu0Chains.addAll(scanFunction(block, ins, from, to, srcLo, srcHi, false));
			}
		});
		forEachFunction(srcLo, srcHi, (block, ins, from, to) -> scanFunction(block, ins, from, to, srcLo, srcHi, true));
	}

	/** Whether the function builds lui r,0x1000 / ori r,r,0x80xx: a VIF0 DMA channel register. */
	private static boolean buildsVif0Address(int[] ins, int from, int to) {
		Set<Integer> hi1000 = new TreeSet<>();
		for (int m = from; m < to; m++) {
			int x = ins[m];
			int op = x >>> 26, rs = (x >>> 21) & 31, rt = (x >>> 16) & 31, imm = x & 0xffff;
			if (op == 0x0f) {
				if (imm == 0x1000) {
					hi1000.add(rt);
				}
				else {
					hi1000.remove(rt);
				}
			}
			else if (op == 0x0d && hi1000.contains(rs) && imm >= 0x8000 && imm < 0x8400) {
				return true;
			}
		}
		return false;
	}

	private boolean isVif0Sender(long target) {
		for (long[] r : vif0Senders) {
			if (target >= r[0] && target < r[1]) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Tracks constants through one EE function. Returns the microcode addresses it points at; when
	 * record is set, also records the program starts and VU0 chains it finds.
	 */
	private Set<Long> scanFunction(MemoryBlock block, int[] ins, int from, int to, long srcLo, long srcHi,
			boolean record) {
		Map<Integer, Long> regs = new HashMap<>();
		Map<Integer, Long> hi = new HashMap<>();
		Set<Long> refs = new TreeSet<>();
		List<long[]> starts = new ArrayList<>();
		long base = block.getStart().getOffset();
		regs.put(0, 0L);
		int clobberAt = -1;
		boolean vif0Call = false;
		for (int m = from; m <= to; m++) {
			if (m == clobberAt) {
				// The call's delay slot has run: a0 is the argument. Then the call clobbers the
				// temporaries and ra; s0-s7, sp and fp survive it.
				if (vif0Call && regs.containsKey(4) && regs.get(4) >= srcLo && regs.get(4) < srcHi && record) {
					vu0Chains.add(regs.get(4));
				}
				vif0Call = false;
				for (int r : new int[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 31 }) {
					regs.remove(r);
					hi.remove(r);
				}
			}
			if (m == to) {
				break;
			}
			int x = ins[m];
			int op = x >>> 26, rs = (x >>> 21) & 31, rt = (x >>> 16) & 31, rd = (x >>> 11) & 31, sa = (x >>> 6) & 31;
			int fn = x & 63, imm = x & 0xffff;
			long simm = (short) imm;
			Integer dst = null;
			Long val = null;
			// vcallms: start the VU0 program at imm15 * 8.
			if ((x & 0xffe0003f) == 0x4a000038) {
				starts.add(new long[] { -1, ((x >>> 6) & 0x7fffL) * 8, m });
				continue;
			}
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
				// jal, jalr: the call happens after the delay slot.
				if (op == 0x03) {
					long target = ((base + 4L * (m + 1)) & 0xf0000000L) | ((x & 0x3ffffffL) << 2);
					vif0Call = isVif0Sender(target);
				}
				clobberAt = m + 2;
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
				starts.add(new long[] { cmd, (val & 0xffff) * 8, m });
			}
		}
		if (record) {
			for (long[] s : starts) {
				Address site = block.getStart().add(4 * s[2]);
				eeCalls.add(s[0] < 0 ? new EeCall("vcallms", s[1], site, Set.of(), "VU0")
					: new EeCall(VIF_CALLS.get((int) s[0]), s[1], site, refs, null));
			}
		}
		return refs;
	}

	/**
	 * Marks the entry point an EE program start names. The entry belongs to the microprograms the
	 * same EE function points at, or failing that to the one upload that covers the address. Such an
	 * entry gets a function if it has none. Otherwise only functions already at that address are
	 * noted, as possible targets.
	 */
	private int applyEeCall(Program vu, String unit, List<Microprogram> programs, List<Microprogram> all,
			EeCall call, List<Function> functions, Map<Function, Map<String, Set<String>>> notes) throws Exception {
		if (call.unit() != null && !call.unit().equals(unit)) {
			return 0;
		}
		// VIF commands carry 16 bits of address; one beyond this unit's memory is not for this unit.
		long address = call.vuAddress();
		if (address >= MEMORY_SIZE.get(unit)) {
			return 0;
		}
		List<Microprogram> named = new ArrayList<>();
		for (Microprogram mp : all) {
			for (long ref : call.vutextRefs()) {
				if (mp.source >= ref && mp.source < chainEnd(ref)) {
					named.add(mp);
				}
			}
		}
		if (named.isEmpty()) {
			List<Microprogram> covering = new ArrayList<>();
			for (Microprogram mp : all) {
				if ((call.unit() == null || mp.unit.equals(call.unit())) && mp.vuAddress <= address && address < mp.end()) {
					covering.add(mp);
				}
			}
			if (covering.size() == 1) {
				named = covering;
			}
		}
		boolean sure = !named.isEmpty();
		int applied = 0;
		for (Microprogram mp : sure ? named : programs) {
			if (!programs.contains(mp)) {
				continue;
			}
			Address a = at(mp, address);
			if (vu.getListing().getInstructionAt(a) == null) {
				continue;
			}
			Function f = vu.getFunctionManager().getFunctionAt(a);
			if (f == null && sure) {
				f = vu.getFunctionManager().createFunction(String.format("%s_%04x", mp.name, a.getOffset()), a,
					new AddressSet(a), SourceType.ANALYSIS);
				functions.add(f);
			}
			if (f == null) {
				continue;
			}
			String key = (sure ? "Started by " : "May be started by ") + call.command() + " at EE";
			notes.computeIfAbsent(f, k -> new TreeMap<>()).computeIfAbsent(key, k -> new TreeSet<>())
					.add(call.site().toString());
			applied++;
		}
		return applied;
	}

	private static void writeNotes(Map<Function, Map<String, Set<String>>> notes) {
		for (Map.Entry<Function, Map<String, Set<String>>> e : notes.entrySet()) {
			List<String> lines = new ArrayList<>();
			for (Map.Entry<String, Set<String>> n : e.getValue().entrySet()) {
				lines.add(n.getKey() + " " + String.join(", ", n.getValue())
					+ (n.getKey().startsWith("May") ? " (it does not say which upload is resident)" : ""));
			}
			e.getKey().setComment(String.join("\n", lines));
		}
	}
}
