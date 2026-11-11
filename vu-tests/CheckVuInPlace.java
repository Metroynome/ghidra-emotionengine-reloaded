// Checks the VU microcode the "PS2 VU Microcode" analyzer (or ImportVuMicrocode.java) built inside an
// EE program: the vu0_* and vu1_* overlays, their functions, the references from EE code, and that
// every VU function decompiles. Functions not named by the importer (FUN_*) came from Ghidra's other
// analyzers and are listed. Run after auto-analysis:
//   GHRUN_ANALYZE=1 ghrun.sh ELF CheckVuInPlace.java -scriptPath vu-tests
//@category PS2

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class CheckVuInPlace extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Map<String, Integer> blocks = new TreeMap<>(), funcs = new TreeMap<>();
		List<String> foreign = new ArrayList<>();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (b.isOverlay() && (b.getName().startsWith("vu0_") || b.getName().startsWith("vu1_"))) {
				blocks.merge(b.getName().substring(0, 3), 1, Integer::sum);
			}
		}
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		int ok = 0, failed = 0, warned = 0, eeRefs = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			String space = f.getEntryPoint().getAddressSpace().getName();
			if (!f.getEntryPoint().getAddressSpace().isOverlaySpace()
				|| !space.startsWith("vu0_") && !space.startsWith("vu1_")) {
				continue;
			}
			String unit = space.substring(0, 3);
			funcs.merge(unit, 1, Integer::sum);
			if (!f.getName().startsWith("mpg_")) {
				foreign.add(f.getName() + "@" + f.getEntryPoint());
			}
			for (Reference r : getReferencesTo(f.getEntryPoint())) {
				if (!r.getFromAddress().getAddressSpace().isOverlaySpace()) {
					eeRefs++;
				}
			}
			DecompileResults d = decomp.decompileFunction(f, 60, monitor);
			if (!d.decompileCompleted() || d.getDecompiledFunction() == null) {
				println("FAILED " + f.getName() + ": " + d.getErrorMessage());
				failed++;
				continue;
			}
			ok++;
			for (String line : d.getDecompiledFunction().getC().split("\n")) {
				if (line.contains("WARNING")) {
					warned++;
				}
			}
			if (f.getName().equals(System.getenv("CHECK_SHOW"))) {
				println("C of " + f.getName() + " (" + f.getCallingConventionName() + "):\n"
					+ d.getDecompiledFunction().getC());
			}
		}
		decomp.dispose();
		// Flow overrides other analyzers put on VU instructions (Shared Return Calls makes CALL_RETURN).
		Map<String, Integer> overrides = new TreeMap<>();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (!b.isOverlay() || !b.getName().startsWith("vu0_") && !b.getName().startsWith("vu1_")) {
				continue;
			}
			for (ghidra.program.model.listing.Instruction insn : currentProgram.getListing()
					.getInstructions(new ghidra.program.model.address.AddressSet(b.getStart(), b.getEnd()), true)) {
				if (insn.getFlowOverride() != ghidra.program.model.listing.FlowOverride.NONE) {
					overrides.merge(insn.getFlowOverride().name(), 1, Integer::sum);
				}
			}
		}
		println("INPLACE flow overrides in VU code " + overrides);
		println("INPLACE overlays " + blocks + "; functions " + funcs + "; EE references to VU functions " + eeRefs);
		println(String.format("INPLACE decompiled %d, failed %d, warning lines %d", ok, failed, warned));
		println("INPLACE functions not made by the importer: " + foreign.size() + " " + foreign);
	}
}
