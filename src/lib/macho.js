// Handles non-fat, 64-bit Mach-O only for now.
// LC_SEGMENT_64 = 0x19, tells you where sections live.

const LC_SEGMENT_64 = 0x19;

export function parseMachoHeader(buf) {
	const dv = new DataView(buf);
	const magic = dv.getUint32(0, false); // read raw bytes as big-endian for comparison

	// Determine endianness based on the magic number and validate that it's a supported Mach-O format
	let le;
	if (magic === 0xcffaedfe) {
		le = true; // MH_MAGIC_64 stored little-endian (normal on Intel/Apple Silicon Macs)
	} 
    else if (magic === 0xfeedfacf) {
		le = false; // MH_MAGIC_64 stored big-endian (rare, old PowerPC-era)
	} 
    else if (magic === 0xcefaedfe) {
		le = true; // MH_MAGIC (32-bit), little-endian
		throw new Error('32-bit Mach-O not supported yet — only 64-bit is implemented');
	} 
    else if (magic === 0xfeedface) {
		le = false; // MH_MAGIC (32-bit), big-endian
		throw new Error('32-bit Mach-O not supported yet — only 64-bit is implemented');
	} 
    else {
		throw new Error('Unrecognized Mach-O magic: ' + magic.toString(16));
	}

	return {
		magic, // The magic number identifying the Mach-O format
		le, // Endianness of the Mach-O file (true for little-endian, false for big-endian)
		cputype: dv.getUint32(0x04, le), // CPU type (e.g., x86_64, arm64)
		cpusubtype: dv.getUint32(0x08, le), // CPU subtype (specific variant of the CPU type)
		filetype: dv.getUint32(0x0c, le), // File type (e.g., executable, dylib, bundle)
		ncmds: dv.getUint32(0x10, le), // Number of load commands in the Mach-O header
		sizeofcmds: dv.getUint32(0x14, le), // Total size of all load commands in bytes
		flags: dv.getUint32(0x18, le), // Flags indicating various attributes of the Mach-O file
		headerSize: 32 // Size of the Mach-O header (fixed at 32 bytes for 64-bit Mach-O)
	};
}

// Read a null-terminated string from the buffer starting at the given offset, with a maximum length
function readCString(buf, offset, maxLen) {
    // Create a Uint8Array view of the buffer starting at the specified offset and limited to maxLen
	const bytes = new Uint8Array(buf, offset, maxLen);
	let end = 0;
    // Iterate through the bytes until a null terminator is found or the maximum length is reached
	while (bytes[end] !== 0 && end < maxLen) end++;
	return new TextDecoder().decode(bytes.slice(0, end));
}

// Parse the sections of a Mach-O binary and return structured information about each section
export function parseMachoSections(buf, hdr) {
	const dv = new DataView(buf);
	let offset = hdr.headerSize;
	const sections = [];

    // Iterate over the number of load commands specified in the Mach-O header
	for (let i = 0; i < hdr.ncmds; i++) {

        // Read the load command type and size from the current offset
		const cmd = dv.getUint32(offset, hdr.le);
		const cmdsize = dv.getUint32(offset + 4, hdr.le);

        // If the load command is a 64-bit segment command, parse its sections
		if (cmd === LC_SEGMENT_64) {
			const segname = readCString(buf, offset + 8, 16); // Read the segment name (16 bytes) from the load command
			const nsects = dv.getUint32(offset + 64, hdr.le); // Number of sections in this segment

			let sectOff = offset + 72; // sizeof(segment_command_64) = 72 bytes
			for (let s = 0; s < nsects; s++) {
				sections.push({
					name: readCString(buf, sectOff, 16), // Read the section name (16 bytes) from the section header
					segment: readCString(buf, sectOff + 16, 16) || segname, // Read the segment name (16 bytes) from the section header or fallback to the segment name
					addr: Number(dv.getBigUint64(sectOff + 32, hdr.le)), // Virtual address of the section in memory
					size: Number(dv.getBigUint64(sectOff + 40, hdr.le)), // Size of the section in bytes
					fileOffset: dv.getUint32(sectOff + 48, hdr.le) // Offset of the section in the file
				});
				sectOff += 80; // sizeof(section_64)
			}
		}

		offset += cmdsize; // Move to the next load command based on the size of the current command
	}

	return sections;
}

// Parse a Mach-O binary and return structured information about it
export function parseMacho(buf) {
	const header = parseMachoHeader(buf); // Parse the Mach-O header to extract metadata about the binary
	const sections = parseMachoSections(buf, header); // Parse the sections of the Mach-O binary to extract information about each section

	// The code section is __text inside the __TEXT segment
	const textSection = sections.find((s) => s.name === '__text');
	if (!textSection) throw new Error('No __text section found');

    // Create a Uint8Array view of the text section bytes from the buffer using the file offset and size of the section
	const textBytes = new Uint8Array(buf, textSection.fileOffset, textSection.size);

	return {
		format: 'macho', // Indicate that the parsed binary is in Mach-O format
		header, // Include the parsed Mach-O header information
		sections, // Include the parsed sections of the Mach-O binary
		symbols: [], // Placeholder for symbols (not implemented yet)
		text: {
			bytes: textBytes, // Uint8Array view of the text section bytes for disassembly
			baseAddr: textSection.addr, // Virtual address of the text section in memory
			fileOffset: textSection.fileOffset, // File offset of the text section in the Mach-O binary
			size: textSection.size // Size of the text section in bytes
		}
	};
}