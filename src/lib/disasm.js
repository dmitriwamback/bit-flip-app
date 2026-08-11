import { loadCapstone, Capstone, Const } from 'capstone-wasm';

let ready = false;

async function ensureLoaded() {
	if (!ready) {
		await loadCapstone();
		ready = true;
	}
}

// Determine the architecture and mode for Capstone based on the parsed binary's format and header information
function resolveArchMode(parsed) {
    
    // ELF binaries
	if (parsed.format === 'elf') {
		switch (parsed.header.e_machine) {
			case 0x3e: // EM_X86_64
				return { arch: Const.CS_ARCH_X86, mode: Const.CS_MODE_64 };
			case 0x03: // EM_386
				return { arch: Const.CS_ARCH_X86, mode: Const.CS_MODE_32 };
			case 0xb7: // EM_AARCH64
				return { arch: Const.CS_ARCH_ARM64, mode: Const.CS_MODE_ARM };
			default:
				throw new Error('Unsupported ELF machine type: ' + parsed.header.e_machine);
		}
	}

    // Mach-O binaries
	if (parsed.format === 'macho') {
		switch (parsed.header.cputype) {
			case 0x01000007: // CPU_TYPE_X86_64
				return { arch: Const.CS_ARCH_X86, mode: Const.CS_MODE_64 };
			case 0x0100000c: // CPU_TYPE_ARM64
				return { arch: Const.CS_ARCH_ARM64, mode: Const.CS_MODE_ARM };
			default:
				throw new Error('Unsupported Mach-O cputype: ' + parsed.header.cputype);
		}
	}

	throw new Error('Unknown format for arch resolution');
}

// Classify an instruction mnemonic into a group: 'call', 'ret', 'jump', 'cmp', or 'normal'
function classify(mnemonic) {
    // Normalize the mnemonic to lowercase for consistent comparison
    const m = mnemonic.toLowerCase();

    // Classify based on common instruction patterns
	if (m === 'call' || m === 'bl' || m === 'blr') return 'call';
	if (m === 'ret' || m === 'retq') return 'ret';
	if (m.startsWith('j') || m.startsWith('b.') || m === 'b' || m === 'cbz' || m === 'cbnz')
		return 'jump';
	if (m.startsWith('cmp') || m === 'test') return 'cmp';
	return 'normal';
}

// Extract a target address from an instruction's operand string
function extractTarget(opStr) {
	const match = opStr && opStr.match(/0x[0-9a-fA-F]+/);
	return match ? parseInt(match[0], 16) : null;
}

// Disassemble the binary and return structured instruction data along with cross-references
export async function disassembleBinary(parsed) {
	await ensureLoaded();

    // Determine the architecture and mode for Capstone based on the parsed binary's format and header information
	const { arch, mode } = resolveArchMode(parsed);
	const cs = new Capstone(arch, mode);

    // Disassemble the text section of the binary using Capstone
	const raw = cs.disasm(parsed.text.bytes, parsed.text.baseAddr);

    // Map the raw disassembled instructions into a structured format with additional metadata
	const instructions = raw.map((insn) => {

        // Classify the instruction and extract its target address if applicable
		const group = classify(insn.mnemonic);
		const target = group === 'jump' || group === 'call' ? extractTarget(insn.opStr) : null;

        // Return a structured representation of the instruction with relevant details
		return {
			address: insn.address,
			bytes: Array.from(insn.bytes)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join(' '),
			mnemonic: insn.mnemonic,
			operands: insn.opStr,
			size: insn.size,
			group,
			target
		};
	});

    // Build a map of cross-references (xrefs) from target addresses to the instructions that reference them
	const xrefs = new Map();

    // Iterate over the disassembled instructions to populate the xrefs map
	for (const insn of instructions) {
		if (insn.target !== null) {
			if (!xrefs.has(insn.target)) xrefs.set(insn.target, []);
			xrefs.get(insn.target).push(insn.address);
		}
	}

    // Return the structured instructions and cross-references for further analysis or display
	return { instructions, xrefs };
}