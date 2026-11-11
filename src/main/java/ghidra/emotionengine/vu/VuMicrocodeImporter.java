package ghidra.emotionengine.vu;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Consumer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;

/**
 * Finds the VU microcode in an EE program and builds it into VU code.
 *
 * The microcode comes as VIF MPG commands, usually in the .vutext section's DMA chains. Each
 * uploads code to a VU micro memory address. Uploads that continue where the previous one ended
 * form one microprogram; an upload to an address already used starts a new one.
 *
 * Each upload runs on VU0 or VU1. An upload is VU0's when EE code passes its DMA chain to a
 * function that writes the VIF0 DMA channel's registers (0x10008000); everything else, and anything
 * too big for VU0's 4 KB of micro memory, is VU1's.
 *
 * Each microprogram becomes an overlay at its VU addresses, so microprograms that share addresses
 * never collide. In place (the R5900 language, whose context register VUMODE selects VU0 or VU1
 * micro mode) the overlays (vu0_*, vu1_*) are added to the EE program itself, and EE code that starts a program
 * gets a reference to it. Otherwise a separate program is made per unit, in the VU:LE:32:VU0 or
 * VU:LE:32:VU1 language.
 *
 * When a microprogram's code flows outside its own upload (into code another upload left resident
 * in micro memory) and exactly one other upload covers that address, that upload is added to the
 * microprogram's overlay too.
 *
 * Functions are made at each microprogram's start, after each E bit (the next program usually
 * starts there), at bal/jalr targets, and at addresses EE code starts: VIF MSCAL, MSCALF and MSCNT
 * commands it builds, and VU0's vcallms. The EE call sites are noted in the function comments.
 */
public class VuMicrocodeImporter {

	public static final String CALLING_CONVENTION = "__vu";
	public static final String OVERLAY_PREFIX_VU0 = "vu0_";
	public static final String OVERLAY_PREFIX_VU1 = "vu1_";

	private static final int VIF_MPG = 0x4a;
	private static final Map<Integer, String> VIF_CALLS = Map.of(0x14, "MSCAL", 0x15, "MSCALF", 0x17, "MSCNT");
	private static final Map<String, Long> MEMORY_SIZE = Map.of("VU0", 0x1000L, "VU1", 0x4000L);

	/** One MPG upload. */
	public static class Upload {
		long source;              // EE address of the MPG command
		long vuAddress;           // VU micro memory address in bytes
		byte[] code;
		String unit;
	}

	/** One microprogram: consecutive uploads to consecutive addresses on one unit. */
	public static class Microprogram {
		public String name;
		public String unit;
		public long source;       // EE address of the first MPG command (or of raw code)
		public long vuAddress;
		ByteArrayOutputStream code = new ByteArrayOutputStream();
		AddressSpace space;       // its overlay space

		long end() {
			return vuAddress + code.size();
		}
	}

	/**
	 * A VU program start EE code makes: the command, the VU address, where the EE code is, the
	 * microcode addresses the same EE function points at, and the unit if the command says (vcallms
	 * is VU0's; a VIF command could be for either VIF).
	 */
	public record EeCall(String command, long vuAddress, Address site, Set<Long> vutextRefs, String unit) {
	}

	/** What one unit's import made. */
	public static class UnitResult {
		public String unit;
		public Program program;
		public List<Microprogram> programs = new ArrayList<>();
		public List<Function> functions = new ArrayList<>();
		public int resident, unresolved, eeApplied, eeUsed;
	}

	private final Program ee;
	private final TaskMonitor monitor;
	private final Consumer<String> log;
	private int uploads, rejected;
	private final List<EeCall> eeCalls = new ArrayList<>();
	private final Set<Long> vu0Chains = new TreeSet<>();
	private final List<long[]> vif0Senders = new ArrayList<>();
	private long srcLo, srcHi;

	public VuMicrocodeImporter(Program ee, TaskMonitor monitor, Consumer<String> log) {
		this.ee = ee;
		this.monitor = monitor;
		this.log = log;
	}

	/** Whether the program's language holds VU micro mode (the R5900 language with VUMODE). */
	public static boolean supportsInPlace(Program program) {
		return program.getRegister("VUMODE") != null;
	}

	/** Whether the program already has VU overlays from an earlier import. */
	public static boolean hasVuOverlays(Program program) {
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			// The R5900 memory map's own vu0.code, vu1.data, ... blocks are not overlays.
			if (b.isOverlay() && (b.getName().startsWith(OVERLAY_PREFIX_VU0) || b.getName().startsWith(OVERLAY_PREFIX_VU1))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Finds microcode in a program that has no .vutext section, such as a raw EE memory dump: runs of
	 * VIF MPG uploads whose data is microcode. An upload must be mostly non-zero words (a stray
	 * 0x4a000000 followed by zeros would otherwise pass as 256 instructions), and a region needs at
	 * least two uploads, each within 0x40 bytes of the previous one's end, as uploads in DMA chains
	 * are. Each region starts at the 16-byte boundary before its first MPG command, to take in the DMA
	 * tag that EE code points at.
	 *
	 * @return [start, end) EE address pairs
	 */
	public static List<long[]> findMicrocode(Program program, TaskMonitor monitor) throws Exception {
		List<long[]> regions = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.isInitialized() || block.isOverlay() || !block.getStart().getAddressSpace().isMemorySpace()
				|| block.getName().startsWith("vu0.") || block.getName().startsWith("vu1.")) {
				continue;
			}
			long base = block.getStart().getOffset();
			byte[] data = new byte[(int) Math.min(block.getSize(), Integer.MAX_VALUE - 8)];
			block.getBytes(block.getStart(), data);
			long regionStart = -1, lastEnd = -1;
			int count = 0;
			for (int i = 4; i + 4 <= data.length; i += 8) {      // MPG data starts on a 64-bit boundary
				if (i % 0x100000 == 4) {
					monitor.checkCancelled();
				}
				int code = word(data, i);
				if (((code >>> 24) & 0x7f) != VIF_MPG) {
					continue;
				}
				int num = (code >>> 16) & 0xff;
				num = num == 0 ? 256 : num;
				long address = (code & 0xffffL) * 8;
				int length = num * 8;
				if (i + 4 + length > data.length || address + length > MEMORY_SIZE.get("VU1")
					|| !isMicrocode(data, i + 4, num) || mostlyZero(data, i + 4, length)) {
					continue;
				}
				long source = base + i, end = source + 4 + length;
				if (lastEnd >= 0 && source - lastEnd <= 0x40) {
					count++;
				}
				else {
					if (count >= 2) {
						regions.add(new long[] { regionStart, (lastEnd + 15) & ~15L });
					}
					regionStart = source & ~15L;
					count = 1;
				}
				lastEnd = end;
				i += length;                                      // resume after the data (still i % 8 == 4)
			}
			if (count >= 2) {
				regions.add(new long[] { regionStart, Math.min((lastEnd + 15) & ~15L, base + data.length) });
			}
		}
		return regions;
	}

	private static boolean mostlyZero(byte[] data, int at, int length) {
		int zero = 0;
		for (int k = 0; k < length; k += 4) {
			if (word(data, at + k) == 0) {
				zero++;
			}
		}
		return zero * 4 > length / 4 * 3;                       // more than 3/4 of the words
	}

	/** The set without the VU overlays, for EE-only analysis. */
	public static ghidra.program.model.address.AddressSetView withoutVuOverlays(Program program,
			ghidra.program.model.address.AddressSetView set) {
		AddressSet vu = new AddressSet();
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (b.isOverlay() && (b.getName().startsWith(OVERLAY_PREFIX_VU0) || b.getName().startsWith(OVERLAY_PREFIX_VU1))) {
				vu.add(b.getStart(), b.getEnd());
			}
		}
		return vu.isEmpty() ? set : set.subtract(vu);
	}

	public int uploads() {
		return uploads;
	}

	public int rejected() {
		return rejected;
	}

	public Set<Long> vu0Chains() {
		return vu0Chains;
	}

	public int vif0Senders() {
		return vif0Senders.size();
	}

	/**
	 * Reads the uploads in [start, start + data.length) and decides each one's unit.
	 *
	 * @param mode "AUTO", "VU0" or "VU1"
	 * @param raw a VU address if the bytes are bare microcode rather than VIF packets, else null
	 * @param scanEe whether to search EE code for VU0 chains and program starts
	 * @return the microprograms, or null (after logging why) if the uploads cannot be on the unit
	 */
	public List<Microprogram> read(Address start, byte[] data, String mode, Long raw, boolean scanEe)
			throws Exception {
		srcLo = start.getOffset();
		srcHi = srcLo + data.length;
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
			return List.of();
		}
		if ((scanEe || mode.equals("AUTO")) && raw == null) {
			scanEe();
		}
		List<String> tooBig = new ArrayList<>();
		for (Upload u : found) {
			u.unit = !mode.equals("AUTO") ? mode : raw == null && inVu0Chain(u) ? "VU0" : "VU1";
			if (u.unit.equals("VU0") && u.vuAddress + u.code.length > MEMORY_SIZE.get("VU0")) {
				if (mode.equals("VU0")) {
					tooBig.add(String.format("%08x (VU 0x%04x-0x%04x)", u.source, u.vuAddress,
						u.vuAddress + u.code.length));
				}
				else {
					log.accept(String.format("The upload at %08x is too big for VU0, so it is VU1's", u.source));
					u.unit = "VU1";
				}
			}
		}
		if (!tooBig.isEmpty()) {
			log.accept(String.format("%d uploads do not fit in VU0's 4 KB of micro memory, so they are not VU0 " +
				"code: %s. Use auto or VU1.", tooBig.size(), String.join(", ", tooBig)));
			return null;
		}
		return group(found, raw != null);
	}

	/**
	 * Builds one unit's microprograms: in the EE program (in place) or in a new program.
	 *
	 * @param target the EE program for in place, else null to make a new program, named name
	 */
	public UnitResult build(String unit, List<Microprogram> programs, List<Microprogram> all, Program target,
			String name, boolean eeEntries, Object consumer) throws Exception {
		UnitResult result = new UnitResult();
		result.unit = unit;
		result.programs = programs;
		boolean inPlace = target != null;
		Program vu = target;
		if (!inPlace) {
			Language language = DefaultLanguageService.getLanguageService()
					.getLanguage(new LanguageID("VU:LE:32:" + unit));
			vu = new ProgramDB(name, language, language.getDefaultCompilerSpec(), consumer);
		}
		result.program = vu;
		Memory memory = vu.getMemory();
		Register vumode = vu.getRegister("VUMODE");
		BigInteger mode = BigInteger.valueOf(unit.equals("VU0") ? 1 : 2);
		String prefix = inPlace ? (unit.equals("VU0") ? OVERLAY_PREFIX_VU0 : OVERLAY_PREFIX_VU1) : "";
		Map<Function, Map<String, Set<String>>> notes = new HashMap<>();
		int tx = vu.startTransaction("Import VU microcode");
		try {
			for (Microprogram mp : programs) {
				Address start = vu.getAddressFactory().getDefaultAddressSpace().getAddress(mp.vuAddress);
				byte[] code = mp.code.toByteArray();
				MemoryBlock block = memory.createInitializedBlock(prefix + mp.name, start,
					new ByteArrayInputStream(code), code.length, monitor, true);
				block.setExecute(true);
				block.setComment(String.format("%s %s at %08x in %s", unit, mp.name.startsWith("raw")
					? "microcode" : "VIF MPG upload", mp.source, ee.getName()));
				mp.space = block.getStart().getAddressSpace();
				setMode(vu, vumode, mode, block);
				disassemble(vu, mp);
			}

			// Code that flows outside its own upload runs code another upload left in micro memory.
			// Add that upload when only one covers the address.
			for (int round = 0; round < 4; round++) {
				Set<Microprogram> changed = new LinkedHashSet<>();
				for (Microprogram mp : programs) {
					for (long target2 : escapes(vu, mp)) {
						Microprogram other = residentFor(vu, programs, mp, target2);
						if (other == null) {
							continue;
						}
						MemoryBlock b = memory.createInitializedBlock(prefix + mp.name + "_" + other.name,
							at(mp, other.vuAddress), new ByteArrayInputStream(other.code.toByteArray()),
							other.code.size(), monitor, false);
						b.setExecute(true);
						b.setComment(String.format("Resident code from the upload at %08x, which %s runs into",
							other.source, mp.name));
						setMode(vu, vumode, mode, b);
						result.resident++;
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
				for (long t : escapes(vu, mp)) {
					result.unresolved++;
					log.accept(String.format("%s flows to 0x%04x, which %s", mp.name, t,
						coveredBy(programs, mp, t).isEmpty() ? "no upload covers"
							: "several uploads cover; none was added"));
				}
			}

			List<Function> functions = result.functions;
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
					for (Address t : insn.getFlows()) {
						if (body.contains(t) && vu.getFunctionManager().getFunctionAt(t) == null
							&& vu.getListing().getInstructionAt(t) != null) {
							functions.add(vu.getFunctionManager().createFunction(
								String.format("%s_sub_%04x", mp.name, t.getOffset()), t,
								new AddressSet(t), SourceType.ANALYSIS));
						}
					}
				}
			}

			if (eeEntries) {
				for (EeCall call : eeCalls) {
					int n = applyEeCall(vu, unit, programs, all, call, functions, notes, inPlace);
					result.eeApplied += n;
					result.eeUsed += n > 0 ? 1 : 0;
				}
				writeNotes(notes);
			}

			for (Function f : functions) {
				CreateFunctionCmd.fixupFunctionBody(vu, f, monitor);
				if (inPlace && vu.getFunctionManager().getCallingConventionNames().contains(CALLING_CONVENTION)) {
					f.setCallingConvention(CALLING_CONVENTION);
				}
			}
			if (!inPlace) {
				GhidraProgramUtilities.markProgramAnalyzed(vu);
			}
		}
		finally {
			vu.endTransaction(tx, true);
		}
		return result;
	}

	private static void setMode(Program vu, Register vumode, BigInteger mode, MemoryBlock block) throws Exception {
		if (vumode != null) {
			vu.getProgramContext().setValue(vumode, block.getStart(), block.getEnd(), mode);
		}
	}

	/** The address in the program's own overlay, even where the overlay has no block yet. */
	private static Address at(Microprogram mp, long offset) {
		return mp.space instanceof OverlayAddressSpace o ? o.getAddressInThisSpaceOnly(offset) : mp.space.getAddress(offset);
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

	private Address eeAddress(long offset) {
		return ee.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	// ---- DMA chains ----

	/**
	 * The end of the DMA chain that starts at ref: cnt tags (id 1) continue to the next tag, an end
	 * tag (id 7) ends after its data. Each tag is 16 bytes followed by QWC quadwords. If ref is not a
	 * tag, the chain is taken to be the 256 bytes from ref.
	 */
	public long chainEnd(long ref) {
		long pos = ref;
		try {
			for (int k = 0; k < 4096; k++) {
				int tag = ee.getMemory().getInt(eeAddress(pos));
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

	private boolean isEe() {
		return ee.getLanguage().getProcessor().toString().toLowerCase().contains("mips")
			|| ee.getLanguage().getLanguageID().toString().toLowerCase().contains("r5900");
	}

	/** One stretch of EE code between jr ra returns, in a block's word array. */
	private interface FunctionVisitor {
		void visit(MemoryBlock block, int[] ins, int from, int to);
	}

	/**
	 * Calls the visitor for each function in the executable blocks: code between jr ra returns,
	 * leaving out the microcode's own words. A raw memory dump is one block holding both the
	 * microcode and the EE code, so only the microcode is left out, not the whole block. VU overlays
	 * from an earlier import are not EE code.
	 */
	private void forEachFunction(FunctionVisitor visitor) throws Exception {
		for (MemoryBlock block : ee.getMemory().getBlocks()) {
			if (!block.isExecute() || !block.isInitialized() || block.isOverlay()
				|| !block.getStart().getAddressSpace().isMemorySpace()) {
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
	private void scanEe() throws Exception {
		if (!isEe()) {
			return;
		}
		forEachFunction((block, ins, from, to) -> {
			if (buildsVif0Address(ins, from, to)) {
				long base = block.getStart().getOffset();
				vif0Senders.add(new long[] { base + 4L * from, base + 4L * to });
				// A sender that names a chain itself sends that chain.
				vu0Chains.addAll(scanFunction(block, ins, from, to, false));
			}
		});
		forEachFunction((block, ins, from, to) -> scanFunction(block, ins, from, to, true));
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
	private Set<Long> scanFunction(MemoryBlock block, int[] ins, int from, int to, boolean record) {
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
	 * noted, as possible targets. In place, the EE instruction also gets a reference to the entry.
	 */
	private int applyEeCall(Program vu, String unit, List<Microprogram> programs, List<Microprogram> all,
			EeCall call, List<Function> functions, Map<Function, Map<String, Set<String>>> notes, boolean inPlace)
			throws Exception {
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
			if (inPlace && sure) {
				vu.getReferenceManager().addMemoryReference(call.site(), a, RefType.DATA, SourceType.ANALYSIS,
					CodeUnit.MNEMONIC);
			}
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

	/** Splits the microprograms by unit, VU0 first. */
	public static Map<String, List<Microprogram>> byUnit(List<Microprogram> all) {
		Map<String, List<Microprogram>> out = new TreeMap<>();
		for (Microprogram mp : all) {
			out.computeIfAbsent(mp.unit, k -> new ArrayList<>()).add(mp);
		}
		return out;
	}
}
