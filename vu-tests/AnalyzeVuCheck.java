// Runs Ghidra's auto-analysis on every VU program in the project root, as a user might, and reports
// whether it changed the functions ImportVuMicrocode.java made. Run after the import, for example:
//   ghrun.sh ELF ImportVuMicrocode.java auto -postScript AnalyzeVuCheck.java -scriptPath vu-tests
//@category PS2

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;

public class AnalyzeVuCheck extends GhidraScript {

	@Override
	protected void run() throws Exception {
		for (DomainFile file : getState().getProject().getProjectData().getRootFolder().getFiles()) {
			if (!file.getName().matches(".*_vu[01](_\\d+)?")) {
				continue;
			}
			Program p = (Program) file.getDomainObject(this, false, false, monitor);
			try {
				boolean flagged = GhidraProgramUtilities.isAnalyzed(p);
				List<String> before = names(p);
				int tx = p.startTransaction("auto-analysis");
				try {
					analyzeAll(p);
				}
				finally {
					p.endTransaction(tx, true);
				}
				List<String> after = names(p);
				List<String> added = new ArrayList<>(after);
				added.removeAll(before);
				List<String> removed = new ArrayList<>(before);
				removed.removeAll(after);
				println(String.format("ANALYZE %s: marked analyzed %s; functions %d -> %d; added %s; removed %s",
					file.getName(), flagged, before.size(), after.size(), added, removed));
			}
			finally {
				p.release(this);
			}
		}
	}

	private static List<String> names(Program p) {
		List<String> out = new ArrayList<>();
		for (Function f : p.getFunctionManager().getFunctions(true)) {
			out.add(f.getName() + "@" + f.getEntryPoint());
		}
		return out;
	}
}
