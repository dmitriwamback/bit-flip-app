import createPatcherModule from './wasm/main.mjs'

let modulePromise = null;
function getModule() {
    if (!modulePromise) {
        modulePromise = createPatcherModule();
    }
    return modulePromise;
}

export async function flipBranch(fileBytes, targetAddr) {
	const mod = await getModule();
	const result = mod.flip_branch(fileBytes, BigInt(targetAddr));
	if (!result) throw new Error('No recognized conditional branch at this address');
	return new Uint8Array(result);
}

export async function nopRange(fileBytes, targetAddr, length) {
	const mod = await getModule();
	const result = mod.nop_range(fileBytes, BigInt(targetAddr), length);
	if (!result) throw new Error('Could not NOP this range (out of bounds or bad length)');
	return new Uint8Array(result);
}

export async function writeBytes(fileBytes, targetAddr, newByteArray) {
	const mod = await getModule();
	const result = mod.write_bytes(fileBytes, BigInt(targetAddr), new Uint8Array(newByteArray));
	if (!result) throw new Error('Write out of bounds');
	return new Uint8Array(result);
}