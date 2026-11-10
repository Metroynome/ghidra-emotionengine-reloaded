// Runs semantic tests in Ghidra's p-code emulator. Script arguments: output path, then a test file.
//
// Test file format, one directive per line ('#' starts a comment):
//   test NAME            start a test
//   code HEXLOWER HEXUPPER   one instruction (words as numbers, e.g. 0x8000033c 0x000002ff)
//   set REG VALUE        initial register value (vfNN_x lanes take float text like 1.5 or 0xHEX)
//   mem ADDR VALUE       initial 32-bit VU data memory word
//   expect REG VALUE     expected register value after the run
//   expectmem ADDR VALUE expected 32-bit VU data memory word
//   run                  execute from address 0 until the program ends or 64 instructions pass
//@category PS2

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;

public class EmuVU extends GhidraScript {

	private PrintWriter out;
	private int passed, failed;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		out = new PrintWriter(args[0]);
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
				case "test" -> {
					name = f[1];
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
			for (int k = 0; k < 64; k++) {
				disassemble(base.add(8 * k));
			}
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			AddressSpace vumem = currentProgram.getAddressFactory().getAddressSpace("vumem");
			for (String[] s : sets) {
				emu.writeRegister(s[1], parseValue(s[1], s[2]));
			}
			for (String[] m : mems) {
				long v = parseValue("mem", m[2]).longValue();
				Address a = vumem.getAddress(Long.decode(m[1]));
				emu.writeMemory(a, new byte[] { (byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24) });
			}
			emu.writeRegister(currentProgram.getLanguage().getProgramCounter(), 0);
			// Run until execution reaches the nop padding past the test code, or the step limit. A
			// program end (E bit) returns to vu_end, so point that at the stop address too.
			Address stop = base.add(8L * code.size() + 8);
			emu.writeRegister("vu_end", BigInteger.valueOf(stop.getOffset()));
			emu.setBreakpoint(stop);
			for (int step = 0; step < 64; step++) {
				Address pc = emu.getExecutionAddress();
				if (pc.getOffset() >= stop.getOffset() || pc.getOffset() >= 8L * 63) {
					break;
				}
				if (!emu.step(monitor)) {
					break;
				}
			}
			List<String> problems = new ArrayList<>();
			for (String[] e : expects) {
				Register r = currentProgram.getRegister(e[1]);
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
				byte[] b = emu.readMemory(vumem.getAddress(Long.decode(e[1])), 4);
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
