// Parse the ELF header and return structured information
export function parseElfHeader(buf) {
	
	// Create a DataView for reading binary data from the buffer
	const dv = new DataView(buf);
	if (dv.getUint32(0, false) !== 0x7f454c46) {
		throw new Error('Not an ELF file (bad magic)');
	}

	// Read the ELF class and data encoding to determine 32/64-bit and endianness
	const eiClass = dv.getUint8(4);
	const eiData = dv.getUint8(5);
	const is64 = eiClass === 2;
	const le = eiData === 1;

	// Validate that the ELF file is 64-bit and little-endian, as only these are supported
	if (!is64) throw new Error('Only 64-bit ELF is supported right now');
	if (!le) throw new Error('Only little-endian ELF is supported right now');

	// Read and return the relevant ELF header fields
	return {
		is64,
		le,
		e_type: dv.getUint16(0x10, le),
		e_machine: dv.getUint16(0x12, le),
		e_entry: Number(dv.getBigUint64(0x18, le)),
		e_phoff: Number(dv.getBigUint64(0x20, le)),
		e_shoff: Number(dv.getBigUint64(0x28, le)),
		e_shentsize: dv.getUint16(0x3a, le),
		e_shnum: dv.getUint16(0x3c, le),
		e_shstrndx: dv.getUint16(0x3e, le)
	};
}

// Read a null-terminated string from the buffer starting at the given offset
function readCString(buf, offset) {

	// Create a Uint8Array view of the buffer starting at the specified offset
	const bytes = new Uint8Array(buf, offset);
	let end = 0;

	// Iterate through the bytes until a null terminator is found or the end of the buffer is reached
	while (bytes[end] !== 0 && offset + end < buf.byteLength) end++;
	return new TextDecoder().decode(bytes.slice(0, end));
}

// ELF section types
const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;


// Parse the section headers of an ELF binary and return structured information about each section
export function parseSectionHeaders(buf, hdr) {

	// Create a DataView for reading binary data from the buffer
	const dv = new DataView(buf);
	const sections = [];

	// Iterate over the number of section headers specified in the ELF header
	for (let i = 0; i < hdr.e_shnum; i++) {
		const base = hdr.e_shoff + i * hdr.e_shentsize;
		sections.push({
			index: i, // Store the index of the section for reference
			nameOff: dv.getUint32(base + 0x00, hdr.le), // Offset into the section header string table for the section name
			type: dv.getUint32(base + 0x04, hdr.le), // Section type (e.g., SHT_SYMTAB, SHT_STRTAB)
			flags: Number(dv.getBigUint64(base + 0x08, hdr.le)), // Section flags (e.g., SHF_ALLOC, SHF_EXECINSTR)
			addr: Number(dv.getBigUint64(base + 0x10, hdr.le)), // Virtual address of the section in memory
			offset: Number(dv.getBigUint64(base + 0x18, hdr.le)), // Offset of the section in the file
			size: Number(dv.getBigUint64(base + 0x20, hdr.le)), // Size of the section in bytes
			link: dv.getUint32(base + 0x28, hdr.le), // Section header index link (e.g., for symbol tables, this points to the associated string table)
			info: dv.getUint32(base + 0x2c, hdr.le), // Additional section-specific information (e.g., for symbol tables, this is the index of the first non-local symbol)
			entsize: Number(dv.getBigUint64(base + 0x38, hdr.le)), // Size of each entry in the section (0 if the section does not contain fixed-size entries)
			name: '' // Placeholder for the section name, to be resolved later using the section header string table
		});
	}

	// Resolve section names via the section header string table
	const shstrtab = sections[hdr.e_shstrndx];
	for (const s of sections) {
		s.name = readCString(buf, shstrtab.offset + s.nameOff);
	}

	return sections;
}

// ELF symbol types
const STT_FUNC = 2;

// Parse the symbol table of an ELF binary and return structured information about each symbol
export function parseSymbols(buf, hdr, sections) {

	// Find the symbol table section (SHT_SYMTAB) and its associated string table (SHT_STRTAB)
	const symtabSec = sections.find((s) => s.type === SHT_SYMTAB);
	if (!symtabSec) return [];

	// Find the linked string table section for symbol names
	const strtabSec = sections[symtabSec.link];
	const dv = new DataView(buf);
	const entrySize = symtabSec.entsize || 24;
	const count = Math.floor(symtabSec.size / entrySize);

	// Iterate over the symbol table entries and extract function symbols with their names, addresses, and sizes
	const symbols = [];
	for (let i = 0; i < count; i++) {
		const base = symtabSec.offset + i * entrySize; // Calculate the offset of the current symbol table entry
		const st_name = dv.getUint32(base + 0x00, hdr.le); // Offset into the string table for the symbol name
		const st_info = dv.getUint8(base + 0x04); // Symbol type and binding information
		const st_value = Number(dv.getBigUint64(base + 0x08, hdr.le)); // Symbol value (address)
		const st_size = Number(dv.getBigUint64(base + 0x10, hdr.le)); // Size of the symbol (e.g., function size)

		// Only include function symbols (STT_FUNC) with a non-zero address in the result
		const type = st_info & 0xf;
		if (type !== STT_FUNC || st_value === 0) continue; // Skip non-function symbols and symbols with no address

		// Add the function symbol to the symbols array with its name, address, and size
		symbols.push({
			name: readCString(buf, strtabSec.offset + st_name),
			address: st_value,
			size: st_size
		});
	}

	// Sort the symbols by address before returning them for easier analysis and display
	return symbols.sort((a, b) => a.address - b.address);
}

// Parse an ELF binary and return structured information including header, sections, symbols, and the .text section
export function parseElf(buf) {
	const header = parseElfHeader(buf); // Parse the ELF header to extract relevant information about the binary
	const sections = parseSectionHeaders(buf, header); // Parse the section headers to get information about each section in the ELF binary
	const symbols = parseSymbols(buf, header, sections); // Parse the symbol table to extract function symbols and their details

	const textSection = sections.find((s) => s.name === '.text'); // Locate the .text section, which contains the executable code of the binary
	if (!textSection) throw new Error('No .text section found'); // Throw an error if the .text section is not found

	const textBytes = new Uint8Array(buf, textSection.offset, textSection.size); // Create a Uint8Array view of the .text section bytes for disassembly

	// Return the parsed ELF information, including header, sections, symbols, and the .text section details
	return {
		header, // The parsed ELF header information
		sections, // The parsed section headers with details about each section
		symbols, // The parsed function symbols with their names, addresses, and sizes
		text: {
			bytes: textBytes, // The raw bytes of the .text section for disassembly
			baseAddr: textSection.addr, // The base virtual address of the .text section in memory
			fileOffset: textSection.offset, // The file offset of the .text section in the ELF binary
			size: textSection.size // The size of the .text section in bytes
		}
	};
}