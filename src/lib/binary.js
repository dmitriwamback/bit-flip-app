import { detectFormat, FORMAT } from './format.js';
import { parseElf } from './elf.js';
import { parseMacho } from './macho.js';

// Disassemble the binary and return structured instruction data along with cross-references
export function parseBinary(buf) {
	const fmt = detectFormat(buf);

    // Determine the binary format and parse accordingly
	switch (fmt) {
		case FORMAT.ELF:
			return { format: 'elf', ...parseElf(buf) };
		case FORMAT.MACHO:
			return parseMacho(buf);
		case FORMAT.MACHO_FAT:
			throw new Error(
				'Universal (fat) Mach-O binary detected — contains multiple architectures. Slice extraction not implemented yet; try compiling with -arch x86_64 or -arch arm64 to force a single-slice binary.'
			);
		default:
			throw new Error('Unrecognized file format (not ELF or Mach-O)');
	}
}