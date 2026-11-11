// Pre-script for headless runs: sets analyzer options before auto-analysis. Arguments are
// NAME:true|false pairs, with '_' standing for a space, for example Shared_Return_Calls:false
// (not '=': Windows batch files split arguments there).
//@category PS2

import ghidra.app.script.GhidraScript;

public class SetAnalyzers extends GhidraScript {

	@Override
	protected void run() throws Exception {
		for (String arg : getScriptArgs()) {
			String[] kv = arg.split(":");
			String name = kv[0].replace('_', ' ');
			setAnalysisOption(currentProgram, name, kv[1]);
			println("analyzer " + name + " = " + kv[1]);
		}
	}
}
