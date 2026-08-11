<script>
	import { parseBinary } from '$lib/binary.js';
	import { disassembleBinary } from '$lib/disasm.js';

	let parsed = $state(null);
	let instructions = $state([]);
	let xrefs = new Map();
	let error = $state(null);
	let fileName = $state('');
	let loading = $state(false);
	let hoveredTarget = $state(null);
	let selectedAddr = $state(null);
	let activeTab = $state('listing'); // 'listing' | 'symbols' | 'sections'

	async function handleFile(e) {
		error = null;
		parsed = null;
		instructions = [];
		const file = e.target.files?.[0];
		if (!file) return;

		fileName = file.name;
		loading = true;
		try {
			const buf = await file.arrayBuffer();
			parsed = parseBinary(buf);

			const result = await disassembleBinary(parsed);
			instructions = result.instructions;
			xrefs = result.xrefs;
			activeTab = 'listing';
		} catch (err) {
			error = err.message;
			console.error(err);
		} finally {
			loading = false;
		}
	}

	function hex(n) {
		return '0x' + Number(n).toString(16).padStart(8, '0');
	}

	function xrefCount(addr) {
		return xrefs.get(addr)?.length ?? 0;
	}

	function isSymbolStart(addr) {
		return parsed?.symbols?.find((s) => s.address === addr);
	}

	function sectionOffset(s) {
		return s.offset !== undefined ? s.offset : s.fileOffset;
	}

	function sectionIsCode(s) {
		return s.name === '.text' || s.name === '__text';
	}

	function labelFor(addr) {
		const sym = isSymbolStart(addr);
		if (sym) return sym.name;
		return 'LAB_' + addr.toString(16).padStart(8, '0');
	}
</script>

<svelte:head>
	<link rel="preconnect" href="https://fonts.googleapis.com" />
	<link
		href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap"
		rel="stylesheet"
	/>
</svelte:head>

<div class="app">
	<div class="toolbar">
		<label class="open-btn">
			<input type="file" accept=".out,.elf,application/octet-stream" onchange={handleFile} />
			📂 Open Binary
		</label>
		{#if fileName}
			<span class="file-chip">{fileName}</span>
		{/if}
		{#if parsed}
			<span class="format-chip">{parsed.format.toUpperCase()}</span>
		{/if}
		<div class="spacer"></div>
		{#if loading}
			<span class="status">analyzing…</span>
		{/if}
		{#if error}
			<span class="status error">{error}</span>
		{/if}
	</div>

	{#if parsed}
		<div class="workspace">
			<aside class="sidebar">
				<div class="sidebar-title">Symbol Tree</div>
				<ul class="tree">
					<li class="tree-branch">Functions ({parsed.symbols.length})</li>
					{#each parsed.symbols as sym}
						<li class="tree-leaf" onclick={() => (selectedAddr = sym.address)}>
							<span class="tree-icon">ƒ</span>{sym.name}
						</li>
					{:else}
						<li class="tree-empty">no symbols (stripped)</li>
					{/each}
					<li class="tree-branch">Sections ({parsed.sections.length})</li>
					{#each parsed.sections as s}
						<li class="tree-leaf">
							<span class="tree-icon">▤</span>{s.name || '(unnamed)'}
						</li>
					{/each}
				</ul>
			</aside>

			<main class="main-panel">
				<div class="panel-tabs">
					<button class:active={activeTab === 'listing'} onclick={() => (activeTab = 'listing')}>
						Listing
					</button>
					<button class:active={activeTab === 'symbols'} onclick={() => (activeTab = 'symbols')}>
						Symbol Table
					</button>
					<button class:active={activeTab === 'sections'} onclick={() => (activeTab = 'sections')}>
						Program Headers
					</button>
				</div>

				{#if activeTab === 'listing'}
					<div class="listing">
						{#each instructions as insn (insn.address)}
							{@const sym = isSymbolStart(insn.address)}
							{#if sym}
								<div class="fn-header">
									<div class="fn-divider"></div>
									<div class="fn-name">{sym.name}</div>
								</div>
							{/if}
							<div
								class="line"
								class:selected={selectedAddr === insn.address}
								class:related={hoveredTarget === insn.address}
								onmouseenter={() => (hoveredTarget = insn.target)}
								onmouseleave={() => (hoveredTarget = null)}
								onclick={() => (selectedAddr = insn.address)}
							>
								<span class="col-cursor"></span>
								<span class="col-addr">{hex(insn.address)}</span>
								<span class="col-bytes">{insn.bytes}</span>
								<span class="col-mnemonic {insn.group}">{insn.mnemonic}</span>
								<span class="col-operands">{insn.operands}</span>
								{#if xrefCount(insn.address) > 0}
									<span class="col-xref">XREF[{xrefCount(insn.address)}]</span>
								{/if}
							</div>
						{/each}
					</div>
				{/if}

				{#if activeTab === 'symbols'}
					<div class="table-wrap">
						{#if parsed.symbols.length === 0}
							<p class="empty">
								No symbol table{parsed.format === 'macho'
									? ' (Mach-O LC_SYMTAB parsing not implemented)'
									: ' — binary is stripped'}.
							</p>
						{:else}
							<table>
								<thead>
									<tr><th>Address</th><th>Size</th><th>Name</th></tr>
								</thead>
								<tbody>
									{#each parsed.symbols as sym}
										<tr>
											<td class="mono">{hex(sym.address)}</td>
											<td class="mono">{sym.size}</td>
											<td class="fn-cell">{sym.name}</td>
										</tr>
									{/each}
								</tbody>
							</table>
						{/if}
					</div>
				{/if}

				{#if activeTab === 'sections'}
					<div class="table-wrap">
						<table>
							<thead>
								<tr>
									<th>Name</th>
									{#if parsed.format === 'macho'}<th>Segment</th>{/if}
									<th>Address</th>
									<th>File Offset</th>
									<th>Size</th>
								</tr>
							</thead>
							<tbody>
								{#each parsed.sections as s}
									<tr class:highlight={sectionIsCode(s)}>
										<td class="mono">{s.name || '(unnamed)'}</td>
										{#if parsed.format === 'macho'}<td class="mono">{s.segment}</td>{/if}
										<td class="mono">{hex(s.addr)}</td>
										<td class="mono">{hex(sectionOffset(s))}</td>
										<td class="mono">{s.size}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			</main>
		</div>
	{:else}
		<div class="empty-workspace">
			<p>Open a compiled ELF or Mach-O binary to begin analysis.</p>
		</div>
	{/if}
</div>

<style>
	:global(html, body) {
		margin: 0;
		background: #d4d0c8;
		font-family: 'Inter', sans-serif;
		color: #1a1a1a;
	}
	:global(*) {
		box-sizing: border-box;
	}

	.app {
		display: flex;
		flex-direction: column;
		height: 100vh;
	}

	/* Toolbar — Swing-style grey chrome */
	.toolbar {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 6px 10px;
		background: #ece9e2;
		border-bottom: 1px solid #b7b2a6;
	}
	.open-btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 5px 12px;
		background: #f5f3ee;
		border: 1px solid #a8a296;
		border-radius: 3px;
		font-size: 0.8rem;
		cursor: pointer;
	}
	.open-btn:hover {
		background: #fffdf8;
	}
	.open-btn input {
		display: none;
	}
	.file-chip, .format-chip {
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.72rem;
		padding: 3px 8px;
		background: #fff;
		border: 1px solid #c7c2b6;
		border-radius: 3px;
		color: #444;
	}
	.format-chip {
		background: #e2e8f0;
		color: #1e4d8b;
	}
	.spacer {
		flex: 1;
	}
	.status {
		font-size: 0.75rem;
		color: #555;
		font-family: 'JetBrains Mono', monospace;
	}
	.status.error {
		color: #a00;
	}

	.workspace {
		flex: 1;
		display: flex;
		min-height: 0;
	}

	/* Sidebar — Symbol Tree */
	.sidebar {
		width: 220px;
		background: #f2f0eb;
		border-right: 1px solid #b7b2a6;
		overflow-y: auto;
	}
	.sidebar-title {
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: #666;
		padding: 8px 10px;
		border-bottom: 1px solid #c7c2b6;
		background: #e8e5de;
	}
	.tree {
		list-style: none;
		margin: 0;
		padding: 4px 0;
		font-size: 0.78rem;
	}
	.tree-branch {
		padding: 6px 10px 2px;
		font-weight: 600;
		color: #555;
		font-size: 0.72rem;
		text-transform: uppercase;
	}
	.tree-leaf {
		padding: 3px 10px 3px 22px;
		cursor: pointer;
		font-family: 'JetBrains Mono', monospace;
		color: #222;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.tree-leaf:hover {
		background: #dce6f2;
	}
	.tree-icon {
		display: inline-block;
		width: 16px;
		color: #7a4fae;
	}
	.tree-empty {
		padding: 4px 22px;
		color: #999;
		font-style: italic;
	}

	/* Main panel */
	.main-panel {
		flex: 1;
		display: flex;
		flex-direction: column;
		min-width: 0;
		background: #fff;
	}
	.panel-tabs {
		display: flex;
		background: #e8e5de;
		border-bottom: 1px solid #b7b2a6;
	}
	.panel-tabs button {
		background: #ded9cf;
		border: none;
		border-right: 1px solid #b7b2a6;
		padding: 6px 16px;
		font-size: 0.78rem;
		color: #444;
		cursor: pointer;
	}
	.panel-tabs button.active {
		background: #fff;
		color: #111;
		font-weight: 600;
		box-shadow: inset 0 -2px 0 #4a90d9;
	}
	.panel-tabs button:focus-visible {
		outline: 2px solid #4a90d9;
	}

	/* Listing view — the core Ghidra-esque piece */
	.listing {
		flex: 1;
		overflow: auto;
		font-family: 'JetBrains Mono', monospace;
		font-size: 0.78rem;
		background: #fdfdfb;
	}
	.fn-header {
		margin-top: 10px;
	}
	.fn-divider {
		border-top: 1px solid #c7c2b6;
		margin: 0 8px;
	}
	.fn-name {
		color: #7a4fae;
		font-weight: 600;
		padding: 4px 12px 2px;
	}
	.line {
		display: grid;
		grid-template-columns: 3px 95px 145px 70px 1fr auto;
		align-items: center;
		gap: 8px;
		padding: 1px 12px 1px 0;
		cursor: pointer;
		border-bottom: 1px solid #f2f0ea;
	}
	.line:nth-child(even) {
		background: #f7f6f2;
	}
	.line:hover {
		background: #eaf1fb;
	}
	.line.selected {
		background: #cfe4ff !important;
	}
	.line.selected .col-cursor {
		background: #4a90d9;
	}
	.line.related {
		background: #dff5df !important;
	}
	.col-cursor {
		align-self: stretch;
	}
	.col-addr {
		color: #000;
	}
	.col-bytes {
		color: #999;
	}
	.col-mnemonic {
		color: #0000cc;
		font-weight: 500;
	}
	.col-mnemonic.call { color: #7a4fae; }
	.col-mnemonic.ret { color: #cc0000; }
	.col-mnemonic.jump { color: #0000cc; }
	.col-mnemonic.cmp { color: #b36b00; }
	.col-operands {
		color: #1a1a1a;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.col-xref {
		color: #1a7a1a;
		font-size: 0.68rem;
		justify-self: end;
	}

	/* Table views */
	.table-wrap {
		flex: 1;
		overflow: auto;
		padding: 10px;
	}
	table {
		border-collapse: collapse;
		width: 100%;
		font-size: 0.8rem;
	}
	th {
		text-align: left;
		background: #e8e5de;
		padding: 5px 10px;
		border: 1px solid #c7c2b6;
		font-size: 0.72rem;
		text-transform: uppercase;
		color: #555;
	}
	td {
		padding: 4px 10px;
		border: 1px solid #ece9e2;
	}
	tr:nth-child(even) td {
		background: #f7f6f2;
	}
	tr.highlight td {
		background: #fff2cc;
	}
	.mono {
		font-family: 'JetBrains Mono', monospace;
	}
	.fn-cell {
		font-family: 'JetBrains Mono', monospace;
		color: #7a4fae;
	}
	.empty {
		color: #777;
		font-size: 0.85rem;
	}

	.empty-workspace {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		color: #777;
		font-size: 0.85rem;
	}
</style>