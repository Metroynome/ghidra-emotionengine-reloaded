// Builds the VU microcode in this EE program into VU code. See VuMicrocodeImporter for how.
//
// In the R5900 language each microprogram becomes an overlay in this program (vu0_* or vu1_*),
// decoded in VU micro mode, and EE code that starts a program gets a reference to it. The "PS2 VU
// Microcode" analyzer does the same for .vutext during auto-analysis; this script is for other
// places or for separate programs. Without a .vutext section, range: or section:, it looks for the
// microcode's DMA chains itself, as the analyzer does (for example in a raw EE memory dump).
//
// Run from the Script Manager, the script shows a dialog with these choices. Headless, they are
// script arguments, all optional, in any order (key:value or key=value):
//   auto | VU0 | VU1   which unit the uploads run on (default auto; VU0 or VU1 puts all on one)
//   separate           make a program per unit (name_vu0, name_vu1) instead of overlays in this one
//   both               do both: overlays in this program, and the separate programs
//   replace            first remove the VU overlays (and EE references to them) an earlier import made
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
		boolean verify = false, eeEntries = true, separate = false, both = false, replace = false;
		String[] args = getScriptArgs();
		if (args.length == 0 && !isRunningHeadless()) {
			args = askOptions();
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
			else if (lower.equals("both")) {
				both = true;
			}
			else if (lower.equals("replace")) {
				replace = true;
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
		boolean alsoSeparate = both && inPlace;
		if (inPlace && replace) {
			println(String.format("Removed %d VU overlays", VuMicrocodeImporter.removeVuOverlays(currentProgram, monitor)));
		}
		if (inPlace && VuMicrocodeImporter.hasVuOverlays(currentProgram)) {
			printerr("This program already has VU code from an earlier import (vu0_* and vu1_* blocks). Run again " +
				"with \"Replace VU code from an earlier import\" ticked, or choose separate programs.");
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
		summary.setLength(0);
		for (long[] region : regions) {
			if (alsoSeparate) {
				importRegion(toAddr(region[0]), region[1], mode, raw, eeEntries, false, verify, show);
			}
			importRegion(toAddr(region[0]), region[1], mode, raw, eeEntries, inPlace, verify, show);
		}
		if (!isRunningHeadless() && summary.length() > 0) {
			popup("VU microcode imported.\n\n" + summary + (inPlace ? "\nIn this program the VU code is in the " +
				"vu0_* and vu1_* blocks (Window > Memory Map). The Console has the details." : ""));
		}
	}

	/** What the run made, for the popup at the end. */
	private final StringBuilder summary = new StringBuilder();

	/** Asks for the options in one dialog, and returns them as script arguments. */
	private String[] askOptions() throws Exception {
		final String where = "Put the VU code";
		final String inside = "Inside this program (recommended)";
		final String apart = "In separate VU0 and VU1 programs";
		final String bothWays = "Both: inside this program and in separate programs";
		final String unit = "Which VU it runs on";
		final String unitAuto = "Work it out from the EE code (recommended)";
		final String unitVu1 = "All on VU1";
		final String unitVu0 = "All on VU0 (only microcode that fits in 4 KB)";
		final String source = "Where the microcode is";
		final String sourceAuto = "Find it (.vutext, or search a memory dump)";
		final String sourceSection = "In a section named below";
		final String sourceRange = "In the address range below";
		final String sourceRaw = "Bare microcode (no VIF packets) in the range below";
		final String sectionName = "Section name";
		final String rangeStart = "Range start (EE address, hex)";
		final String rangeEnd = "Range end (EE address, hex, not included)";
		final String rawAddress = "Bare microcode's VU address (hex)";
		final String replaceIt = "Replace VU code from an earlier import";
		final String entries = "Link the EE code that starts each VU program";
		final String check = "Decompile every VU function and print a check (slow)";

		boolean inPlaceOk = VuMicrocodeImporter.supportsInPlace(currentProgram);
		boolean earlier = VuMicrocodeImporter.hasVuOverlays(currentProgram);
		ghidra.features.base.values.GhidraValuesMap values = new ghidra.features.base.values.GhidraValuesMap();
		if (inPlaceOk) {
			values.defineChoice(where, inside, inside, apart, bothWays);
		}
		else {
			values.defineChoice(where, apart, apart);
		}
		values.defineChoice(unit, unitAuto, unitAuto, unitVu1, unitVu0);
		values.defineChoice(source, sourceAuto, sourceAuto, sourceSection, sourceRange, sourceRaw);
		values.defineString(sectionName, ".vutext");
		values.defineString(rangeStart, "");
		values.defineString(rangeEnd, "");
		values.defineString(rawAddress, "0");
		values.defineBoolean(replaceIt, earlier);
		values.defineBoolean(entries, true);
		values.defineBoolean(check, false);
		values.setValidator((map, status) -> {
			String src = map.getChoice(source);
			if (src.equals(sourceSection) && map.getString(sectionName).isBlank()) {
				status.setStatusText("Enter the section name.");
				return false;
			}
			if ((src.equals(sourceRange) || src.equals(sourceRaw))
				&& (!isHex(map.getString(rangeStart)) || !isHex(map.getString(rangeEnd)))) {
				status.setStatusText("Enter the range start and end as hex addresses, for example 100080 and 11a160.");
				return false;
			}
			if (src.equals(sourceRaw) && !isHex(map.getString(rawAddress))) {
				status.setStatusText("Enter the VU address of the bare microcode in hex, usually 0.");
				return false;
			}
			if (!map.getChoice(where).equals(apart) && !map.getBoolean(replaceIt) && earlier) {
				status.setStatusText("This program already has VU code: tick \"" + replaceIt + "\" to import it again.");
				return false;
			}
			return true;
		});
		String message = "<html>Decodes the PlayStation 2 Vector Unit (VU0/VU1) microcode stored in this program.<br><br>" +
			"<b>Inside this program</b> adds each VU program as a block (vu0_* or vu1_*) at its VU address,<br>" +
			"with functions and links from the EE code that starts it. <b>Separate programs</b> are saved<br>" +
			"next to this one, named " + currentProgram.getName() + "_vu0 and _vu1, to view the VU code on its own.<br><br>" +
			"The defaults suit a game ELF or an EE memory dump." +
			(earlier ? "<br><br>This program already has VU code from an earlier import." : "") +
			(!inPlaceOk ? "<br><br>This program's language cannot hold VU code, so only separate programs can be made." : "");
		askValues("Import VU microcode", message, values);

		List<String> out = new ArrayList<>();
		String w = values.getChoice(where);
		out.add(w.equals(apart) ? "separate" : w.equals(bothWays) ? "both" : "");
		String u = values.getChoice(unit);
		out.add(u.equals(unitVu1) ? "VU1" : u.equals(unitVu0) ? "VU0" : "auto");
		String src = values.getChoice(source);
		if (src.equals(sourceSection)) {
			out.add("section:" + values.getString(sectionName).trim());
		}
		else if (src.equals(sourceRange) || src.equals(sourceRaw)) {
			out.add("range:" + values.getString(rangeStart).trim() + "-" + values.getString(rangeEnd).trim());
			if (src.equals(sourceRaw)) {
				out.add("raw:" + values.getString(rawAddress).trim());
			}
		}
		if (values.getBoolean(replaceIt)) {
			out.add("replace");
		}
		if (!values.getBoolean(entries)) {
			out.add("noentries");
		}
		if (values.getBoolean(check)) {
			out.add("verify");
		}
		return out.toArray(new String[0]);
	}

	private static boolean isHex(String s) {
		try {
			Long.decode(hex(s.trim()));
			return !s.isBlank();
		}
		catch (NumberFormatException e) {
			return false;
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
			if (importer.assumedUploads() > 0) {
				println(String.format("%d uploads that no EE code here sends: VU1 assumed (noted in their comments)",
					importer.assumedUploads()));
				if (inPlace) {
					summary.append(String.format("%d uploads are not sent by any EE code here, so VU1 was assumed; " +
						"their comments say so.%n", importer.assumedUploads()));
				}
			}
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
			summary.append(String.format("%s: %d microprograms, %d functions %s%n", unit, r.programs.size(),
				r.functions.size(), inPlace ? "in this program" : "in the separate program"));
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
		summary.append("    saved as " + saved.getPathname() + "\n");
	}

	private static String hex(String s) {
		return s.startsWith("0x") || s.startsWith("0X") ? s : "0x" + s;
	}
}
