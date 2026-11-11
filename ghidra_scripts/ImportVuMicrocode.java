// Builds the VU microcode in this EE program into VU code. See VuMicrocodeImporter for how.
//
// In the R5900 language each microprogram becomes an overlay in this program (vu0_* or vu1_*),
// decoded in VU micro mode, and EE code that starts a program gets a reference to it. The "PS2 VU
// Microcode" analyzer does the same for .vutext during auto-analysis; this script is for other
// places or for separate programs. Without a .vutext section, range: or section:, it looks for the
// microcode's DMA chains itself, as the analyzer does (for example in a raw EE memory dump).
//
// Script arguments, all optional, in any order (key:value or key=value). Run from the Script
// Manager without arguments, the script asks for them.
//   auto | VU0 | VU1   which unit the uploads run on (default auto; VU0 or VU1 puts all on one)
//   separate           make a program per unit (name_vu0, name_vu1) instead of overlays in this one
//   section:NAME       read microcode from this EE section instead of .vutext
//   range:START-END    read microcode from these EE addresses (hex, END exclusive)
//   raw:VUADDR         the bytes are bare microcode for VU address VUADDR (hex), not VIF packets
//   noentries          do not mark entry points that EE code starts
//   verify             decompile every function and print a summary, as the tests do
//   show:FUNCTION      with verify, print that function's C
//@category ghidra-emotionengine

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.emotionengine.vu.VuMicrocodeImporter;
import ghidra.emotionengine.vu.VuMicrocodeImporter.Microprogram;
import ghidra.emotionengine.vu.VuMicrocodeImporter.UnitResult;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class ImportVuMicrocode extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String mode = "AUTO", section = null, show = null;
		Address rangeStart = null, rangeEnd = null;
		Long raw = null;
		boolean verify = false, eeEntries = true, separate = false;
		String[] args = getScriptArgs();
		if (args.length == 0 && !isRunningHeadless()) {
			args = askString("Import VU microcode", "Options: auto | VU0 | VU1, separate, section:NAME, " +
				"range:START-END, raw:VUADDR, noentries, verify", "auto").trim().split("\\s+");
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
			else if (lower.equals("separate")) {
				separate = true;
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
		boolean inPlace = !separate && VuMicrocodeImporter.supportsInPlace(currentProgram);
		if (inPlace && VuMicrocodeImporter.hasVuOverlays(currentProgram)) {
			printerr("This program already has VU overlays (vu0_*, vu1_*). Remove them first, or use separate.");
			return;
		}

		// The bytes to read: a range, a section (.vutext by default), or, with neither, the regions
		// of microcode found in the program (as in a raw EE memory dump).
		List<long[]> regions = new ArrayList<>();
		if (rangeStart != null) {
			regions.add(new long[] { rangeStart.getOffset(), rangeEnd.getOffset() });
		}
		else {
			String blockName = section != null ? section : ".vutext";
			MemoryBlock block = currentProgram.getMemory().getBlock(blockName);
			if (block != null) {
				regions.add(new long[] { block.getStart().getOffset(), block.getEnd().getOffset() + 1 });
			}
			else if (section != null || raw != null) {
				printerr("This program has no " + blockName + " section. Give section= or range=.");
				return;
			}
			else {
				regions.addAll(VuMicrocodeImporter.findMicrocode(currentProgram, monitor));
				for (long[] r : regions) {
					println(String.format("Microcode found at %08x-%08x", r[0], r[1]));
				}
				if (regions.isEmpty()) {
					printerr("This program has no .vutext section and no microcode was found. Give range=.");
					return;
				}
			}
		}
		for (long[] region : regions) {
			importRegion(toAddr(region[0]), region[1], mode, raw, eeEntries, inPlace, verify, show);
		}
	}

	private void importRegion(Address sourceStart, long end, String mode, Long raw, boolean eeEntries,
			boolean inPlace, boolean verify, String show) throws Exception {
		byte[] data = new byte[(int) (end - sourceStart.getOffset())];
		currentProgram.getMemory().getBytes(sourceStart, data);

		VuMicrocodeImporter importer = new VuMicrocodeImporter(currentProgram, monitor, this::println);
		List<Microprogram> all = importer.read(sourceStart, data, mode, raw, eeEntries);
		if (all == null) {
			return;
		}
		if (all.isEmpty()) {
			printerr("No VIF MPG uploads found.");
			return;
		}
		println(String.format("%d MPG uploads became %d microprograms", importer.uploads(), all.size()));
		if (importer.rejected() > 0) {
			println(String.format("Skipped %d MPG-like words whose data is not microcode", importer.rejected()));
		}
		if (mode.equals("AUTO") && raw == null) {
			println(String.format("VU0: %d chains sent through VIF0 by %d EE functions", importer.vu0Chains().size(),
				importer.vif0Senders()));
			for (long chain : importer.vu0Chains()) {
				println(String.format("VU0 chain %08x-%08x", chain, importer.chainEnd(chain)));
			}
		}
		for (Map.Entry<String, List<Microprogram>> e : VuMicrocodeImporter.byUnit(all).entrySet()) {
			String unit = e.getKey();
			String name = currentProgram.getName() + "_" + unit.toLowerCase();
			UnitResult r = importer.build(unit, e.getValue(), all, inPlace ? currentProgram : null, name,
				eeEntries && raw == null, this);
			println(String.format("%s: %d microprograms %s", unit, r.programs.size(),
				inPlace ? "in this program" : "in " + name));
			println(String.format("%s: resident uploads added: %d; flows left outside the program: %d", unit,
				r.resident, r.unresolved));
			if (eeEntries && raw == null) {
				println(String.format("%s: %d EE program starts apply; %d marked entry points", unit, r.eeUsed,
					r.eeApplied));
			}
			if (verify) {
				verify(unit, r, show);
			}
			if (!inPlace) {
				save(r.program, name);
				r.program.release(this);
			}
		}
	}

	private void verify(String unit, UnitResult r, String show) {
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(r.program);
		int ok = 0, failed = 0, warned = 0;
		for (Function f : r.functions) {
			DecompileResults d = decomp.decompileFunction(f, 60, monitor);
			if (!d.decompileCompleted() || d.getDecompiledFunction() == null) {
				println("FAILED " + f.getName() + ": " + d.getErrorMessage());
				failed++;
				continue;
			}
			ok++;
			println("FUNCTION " + unit + " " + f.getName() + " at " + f.getEntryPoint()
				+ (f.getComment() != null ? " // " + f.getComment().replace("\n", " | ") : ""));
			String c = d.getDecompiledFunction().getC();
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

	/** Saves a separate VU program next to the EE program, under a free name. */
	private void save(Program vu, String name) throws Exception {
		if (getState().getProject() == null) {
			return;
		}
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

	private static String hex(String s) {
		return s.startsWith("0x") || s.startsWith("0X") ? s : "0x" + s;
	}
}
