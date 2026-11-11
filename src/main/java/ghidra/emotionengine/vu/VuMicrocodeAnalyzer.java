package ghidra.emotionengine.vu;

import java.util.List;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Builds the VU microcode in an EE program's .vutext into VU code in the same program: each
 * microprogram becomes an overlay at its VU0 or VU1 micro memory addresses, decoded in micro mode,
 * with functions at its entry points and references from the EE code that starts it. See
 * {@link VuMicrocodeImporter}.
 */
public class VuMicrocodeAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "PS2 VU Microcode";
	private static final String DESCRIPTION =
		"Decodes the VU0 and VU1 microcode uploaded by the VIF MPG commands in .vutext. Each microprogram " +
		"becomes an overlay (vu0_* or vu1_*) at its VU micro memory addresses, with functions at its entry " +
		"points and references from the EE code that starts it (VIF MSCAL, vcallms).";

	public VuMicrocodeAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// After the EE code is disassembled, so the EE program starts can be found; the scan reads
		// bytes, so it does not depend on other analysis.
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return VuMicrocodeImporter.supportsInPlace(program) && program.getMemory().getBlock(".vutext") != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		if (VuMicrocodeImporter.hasVuOverlays(program)) {
			return true;
		}
		MemoryBlock vutext = program.getMemory().getBlock(".vutext");
		if (vutext == null || !vutext.isInitialized() || !set.intersects(vutext.getStart(), vutext.getEnd())) {
			return false;
		}
		try {
			byte[] data = new byte[(int) vutext.getSize()];
			vutext.getBytes(vutext.getStart(), data);
			VuMicrocodeImporter importer = new VuMicrocodeImporter(program, monitor, s -> log.appendMsg(NAME, s));
			List<VuMicrocodeImporter.Microprogram> all = importer.read(vutext.getStart(), data, "AUTO", null, true);
			if (all == null || all.isEmpty()) {
				return false;
			}
			for (Map.Entry<String, List<VuMicrocodeImporter.Microprogram>> e : VuMicrocodeImporter.byUnit(all)
					.entrySet()) {
				monitor.checkCancelled();
				VuMicrocodeImporter.UnitResult r = importer.build(e.getKey(), e.getValue(), all, program, null, true, this);
				log.appendMsg(NAME, String.format("%s: %d microprograms, %d functions", e.getKey(), r.programs.size(),
					r.functions.size()));
			}
			return true;
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendException(e);
			return false;
		}
	}
}
