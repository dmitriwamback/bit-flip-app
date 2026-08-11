export const FORMAT = {
	ELF: 'elf',
	MACHO: 'macho',
	MACHO_FAT: 'macho_fat',
	UNKNOWN: 'unknown'
};

export function detectFormat(buf) {
	const dv = new DataView(buf);
	const magic32 = dv.getUint32(0, false); // big-endian read for comparison

	if (magic32 === 0x7f454c46) return FORMAT.ELF;
	if (magic32 === 0xfeedface || magic32 === 0xfeedfacf) return FORMAT.MACHO; // 32/64-bit, native-endian header
	if (magic32 === 0xcefaedfe || magic32 === 0xcffaedfe) return FORMAT.MACHO; // 32/64-bit, swapped-endian header
	if (magic32 === 0xcafebabe || magic32 === 0xbebafeca) return FORMAT.MACHO_FAT; // universal binary

	return FORMAT.UNKNOWN;
}