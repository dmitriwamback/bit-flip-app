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

	const { arch, mode } = resolveArchMode(parsed);
	const cs = new Capstone(arch, mode);

	const raw = cs.disasm(parsed.text.bytes, parsed.text.baseAddr);

	// Capstone-wasm returns insn.address as an offset relative to the
	// start of the buffer (0-based), NOT the real virtual address, even
	// though we passed baseAddr in. Re-apply it manually here so every
	// address in the app (rows, xrefs, patch targets) is a real vaddr.
	const base = parsed.text.baseAddr;

	const instructions = raw.map((insn) => {
		const group = classify(insn.mnemonic);
		const rawTarget = group === 'jump' || group === 'call' ? extractTarget(insn.opStr) : null;

		// jump/call targets embedded in the operand string were computed
		// by Capstone using the same wrong 0-based frame, so they need
		// the identical correction to stay consistent with `address`.
		const target = rawTarget !== null ? base + rawTarget : null;

		return {
			address: base + insn.address, // <-- corrected
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

	const xrefs = new Map();
	for (const insn of instructions) {
		if (insn.target !== null) {
			if (!xrefs.has(insn.target)) xrefs.set(insn.target, []);
			xrefs.get(insn.target).push(insn.address);
		}
	}

	return { instructions, xrefs };
}

export function reslice(parsed, fullFileBytes) {
	const sec = parsed.sections.find(
		(s) => s.name === '.text' || s.name === '__text'
	);
	if (!sec) throw new Error('Could not find .text/__text section to reslice');

	const fileOffset = sec.offset !== undefined ? sec.offset : sec.fileOffset;

	return {
		...parsed,
		text: {
			...parsed.text,
			bytes: fullFileBytes.slice(fileOffset, fileOffset + sec.size)
		}
	};
}