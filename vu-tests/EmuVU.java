// Runs semantic tests in Ghidra's p-code emulator. Script arguments: output path, a test file, and
// for the R5900 language the unit (VU0 or VU1) whose micro mode to test.
//
// Test file format, one directive per line ('#' starts a comment):
//   test NAME            start a test
//   code HEXLOWER HEXUPPER   one instruction (words as numbers, e.g. 0x8000033c 0x000002ff)
//   set REG VALUE        initial register value (vfNN_x lanes take float text like 1.5 or 0xHEX)
//   mem ADDR VALUE       initial 32-bit VU data memory word
//   expect REG VALUE     expected register value after the run ("xgkick" checks the last xgkick)
//   expectmem ADDR VALUE expected 32-bit VU data memory word
//   only UNIT            run this test only on that language (VU0 or VU1)
//   run                  execute from address 0 until the program ends or 64 instructions pass
//@category PS2

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class EmuVU extends GhidraScript {

	private PrintWriter out;
	private int passed, failed;
	private Long lastKick;
	private String only;
	/** VU0 or VU1 when testing microcode inside the R5900 language (the VUMODE context); else null. */
	private String embedded;

	/** The register a test names (standalone VU language name) in the language under test. */
	private String reg(String name) {
		if (embedded == null || name.equals("pc")) {
			return name;
		}
		if (embedded.equals("VU1")) {
			return "vu1_" + name;
		}
		// VU0 micro mode uses the COP2 registers VU0 macro mode uses (see gen_slaspec.py regmap).
		java.util.regex.Matcher m = java.util.regex.Pattern.compile("vf(\\d\\d)_([xyzw])").matcher(name);
		if (m.matches()) {
			return "vf" + Integer.parseInt(m.group(1)) + m.group(2);
		}
		m = java.util.regex.Pattern.compile("acc_([xyzw])").matcher(name);
		if (m.matches()) {
			return "vuACC" + m.group(1);
		}
		Map<String, String> cop2 = Map.of("q", "vuQ", "p", "P", "i", "vuI", "r", "vuR", "status", "vuStatus_32",
			"mac", "vuMAC", "clip", "vuCF");
		return cop2.getOrDefault(name, "vu0_" + name);
	}

	/** Where VU data memory address a is in the language under test. */
	private Address dataAddress(long a) {
		if (embedded == null) {
			return currentProgram.getAddressFactory().getAddressSpace("vumem").getAddress(a);
		}
		return toAddr((embedded.equals("VU0") ? 0x11004000L : 0x1100c000L) + a);
	}

	/** A CALLOTHER that maps one 32-bit float to another. */
	private static class FloatOp extends BreakCallBack {
		private final java.util.function.DoubleUnaryOperator f;

		FloatOp(java.util.function.DoubleUnaryOperator f) {
			this.f = f;
		}

		@Override
		public boolean pcodeCallback(PcodeOpRaw op) {
			MemoryState m = emulate.getMemoryState();
			float x = Float.intBitsToFloat((int) m.getValue(op.getInput(1)));
			m.setValue(op.getOutput(), Float.floatToRawIntBits((float) f.applyAsDouble(x)) & 0xffffffffL);
			return true;
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		out = new PrintWriter(args[0]);
		embedded = args.length > 2 ? args[2].toUpperCase() : null;
		List<String> lines = Files.readAllLines(new File(args[1]).toPath());
		String name = null;
		List<long[]> code = new ArrayList<>();
		List<String[]> sets = new ArrayList<>(), mems = new ArrayList<>(), expects = new ArrayList<>(),
			expectMems = new ArrayList<>();
		for (String raw : lines) {
			String line = raw.replaceAll("#.*", "").trim();
			if (line.isEmpty()) {
				continue;
			}
			String[] f = line.split("\\s+");
			switch (f[0]) {
				case "only" -> only = f[1];
				case "test" -> {
					name = f[1];
					only = null;
					code.clear(); sets.clear(); mems.clear(); expects.clear(); expectMems.clear();
				}
				case "code" -> code.add(new long[] { Long.decode(f[1]), Long.decode(f[2]) });
				case "set" -> sets.add(f);
				case "mem" -> mems.add(f);
				case "expect" -> expects.add(f);
				case "expectmem" -> expectMems.add(f);
				case "run" -> runTest(name, code, sets, mems, expects, expectMems);
				default -> throw new IllegalArgumentException("bad line: " + raw);
			}
		}
		out.printf("passed %d, failed %d%n", passed, failed);
		out.close();
	}

	private static BigInteger parseValue(String reg, String text) {
		if (text.startsWith("0x") || text.startsWith("-0x") || !text.contains(".") && !reg.matches(".*_[xyzw]$|q|p|i")) {
			return BigInteger.valueOf(Long.decode(text) & 0xffffffffL);
		}
		return BigInteger.valueOf(Float.floatToRawIntBits(Float.parseFloat(text)) & 0xffffffffL);
	}

	private void runTest(String name, List<long[]> code, List<String[]> sets, List<String[]> mems,
			List<String[]> expects, List<String[]> expectMems) throws Exception {
		// Write the code into program memory (address 0 onward), with nop padding after it.
		if (only != null && !(embedded != null ? embedded : currentProgram.getLanguageID().toString()).endsWith(only)) {
			out.printf("SKIP %s (%s only)%n", name, only);
			return;
		}
		Address base = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0);
		int tx = currentProgram.startTransaction("test " + name);
		try {
			clearListing(base, base.add(8 * 64 - 1));
			for (int k = 0; k < 64; k++) {
				long lower = k < code.size() ? code.get(k)[0] : 0x8000033cL;
				long upper = k < code.size() ? code.get(k)[1] : 0x000002ffL;
				setInt(base.add(8 * k), (int) lower);
				setInt(base.add(8 * k + 4), (int) upper);
			}
			ghidra.program.model.lang.Register vumode = currentProgram.getRegister("VUMODE");
			if (embedded != null) {
				// Each test reuses these addresses: drop the E-bit marks an earlier test left.
				currentProgram.getProgramContext().remove(base, base.add(8 * 64 - 1),
					currentProgram.getRegister("VU_ENDSLOT"));
				currentProgram.getProgramContext().setValue(vumode, base, base.add(8 * 64 - 1),
					BigInteger.valueOf(embedded.equals("VU0") ? 1 : 2));
			}
			for (int k = 0; k < 64; k++) {
				disassemble(base.add(8 * k));
			}
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		lastKick = null;
		try {
			// The language leaves EFU transcendentals and xgkick as p-code operations. Model them
			// here as the VU manual defines them, so tests can run code that uses them: esin is sin,
			// eatan is atan, eexp is e^-x. xgkick is recorded; "expect xgkick ADDRESS" checks it.
			emu.registerCallOtherCallback("vu_sin", new FloatOp(x -> Math.sin(x)));
			emu.registerCallOtherCallback("vu_atan", new FloatOp(x -> Math.atan(x)));
			emu.registerCallOtherCallback("vu_exp", new FloatOp(x -> Math.exp(-x)));
			emu.registerCallOtherCallback("vu_xgkick", new BreakCallBack() {
				@Override
				public boolean pcodeCallback(PcodeOpRaw op) {
					lastKick = emulate.getMemoryState().getValue(op.getInput(1));
					return true;
				}
			});
			for (String[] s : sets) {
				emu.writeRegister(reg(s[1]), parseValue(s[1], s[2]));
			}
			for (String[] m : mems) {
				long v = parseValue("mem", m[2]).longValue();
				Address a = dataAddress(Long.decode(m[1]));
				emu.writeMemory(a, new byte[] { (byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24) });
			}
			emu.writeRegister(currentProgram.getLanguage().getProgramCounter(), 0);
			// Run until execution reaches the nop padding past the test code, or the step limit. A
			// program end (E bit) returns to vu_end, so point that at the stop address too.
			Address stop = base.add(8L * code.size() + 8);
			emu.writeRegister(reg("vu_end"), BigInteger.valueOf(stop.getOffset()));
			emu.setBreakpoint(stop);
			for (int step = 0; step < 64; step++) {
				Address pc = emu.getExecutionAddress();
				if (pc.getOffset() >= stop.getOffset() || pc.getOffset() >= 8L * 63) {
					break;
				}
				// EmulatorHelper decodes a branch target with the language's default context, so in
				// the R5900 language it would read VU microcode as EE code; take the address's
				// context from the program instead.
				if (embedded != null) {
					ghidra.program.model.lang.RegisterValue ctx = currentProgram.getProgramContext()
							.getDisassemblyContext(pc);
					emu.setContextRegister(ctx);
				}
				if (System.getenv("EMU_TRACE") != null && name.equals(System.getenv("EMU_TRACE"))) {
					Instruction ti = getInstructionAt(pc);
					out.printf("TRACE %s %s ctx=%s%n", pc, ti, emu.getContextRegister());
				}
				if (!emu.step(monitor)) {
					if (System.getenv("EMU_TRACE") != null) {
						out.printf("STEP FAILED at %s: %s%n", emu.getExecutionAddress(), emu.getLastError());
					}
					break;
				}
				if (System.getenv("EMU_TRACE") != null && name.equals(System.getenv("EMU_TRACE"))) {
					out.printf("AFTER pc=%s vi03=%s vi02=%s%n", emu.getExecutionAddress(),
						emu.readRegister(reg("vi03")), emu.readRegister(reg("vi02")));
				}
			}
			List<String> problems = new ArrayList<>();
			for (String[] e : expects) {
				if (e[1].equals("xgkick")) {
					long want = Long.decode(e[2]);
					if (lastKick == null || lastKick != want) {
						problems.add(String.format("xgkick=%s want 0x%x", lastKick == null ? "none"
							: String.format("0x%x", lastKick), want));
					}
					continue;
				}
				Register r = currentProgram.getRegister(reg(e[1]));
				BigInteger got = emu.readRegister(r);
				BigInteger want = parseValue(e[1], e[2]);
				if (r.getBitLength() < 32) {
					want = want.and(BigInteger.ONE.shiftLeft(r.getBitLength()).subtract(BigInteger.ONE));
				}
				if (!got.equals(want)) {
					problems.add(String.format("%s=0x%x want 0x%x", e[1], got, want));
				}
			}
			for (String[] e : expectMems) {
				byte[] b = emu.readMemory(dataAddress(Long.decode(e[1])), 4);
				long got = (b[0] & 0xff) | (b[1] & 0xff) << 8 | (b[2] & 0xff) << 16 | (long) (b[3] & 0xff) << 24;
				long want = parseValue("mem", e[2]).longValue();
				if (got != want) {
					problems.add(String.format("mem[%s]=0x%x want 0x%x", e[1], got, want));
				}
			}
			if (problems.isEmpty()) {
				passed++;
				out.printf("PASS %s%n", name);
			}
			else {
				failed++;
				out.printf("FAIL %s: %s%n", name, String.join(", ", problems));
			}
		}
		catch (Exception ex) {
			failed++;
			out.printf("FAIL %s: %s%n", name, ex);
		}
		finally {
			emu.dispose();
		}
	}
}
