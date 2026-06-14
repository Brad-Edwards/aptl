<script lang="ts">
	import { onMount } from 'svelte';
	import type { Role } from '$lib/console/types';
	import {
		consoleState,
		consoleError,
		consoleLoading,
		refreshConsole
	} from '$lib/stores/console';
	import {
		createSession,
		deleteSession,
		updateSession,
		createScratchpad,
		updateScratchpad,
		deleteScratchpad
	} from '$lib/console/api';
	import SessionSidebar from '$lib/components/console/SessionSidebar.svelte';
	import ChatPane from '$lib/components/console/ChatPane.svelte';
	import McpAccessPanel from '$lib/components/console/McpAccessPanel.svelte';
	import ScratchpadPanel from '$lib/components/console/ScratchpadPanel.svelte';

	let selectedId = $state<string | null>(null);

	const selected = $derived(
		$consoleState.sessions.find((s) => s.id === selectedId) ?? null
	);

	onMount(async () => {
		try {
			const state = await refreshConsole();
			if (state.sessions.length > 0) selectedId = state.sessions[0].id;
		} catch {
			// error surfaced via store
		}
	});

	async function reload() {
		await refreshConsole();
	}

	async function handleCreate(role: Role) {
		const session = await createSession({ role });
		await reload();
		selectedId = session.id;
	}

	async function handleDelete(id: string) {
		await deleteSession(id);
		if (selectedId === id) selectedId = null;
		await reload();
		if (!selectedId && $consoleState.sessions.length > 0) {
			selectedId = $consoleState.sessions[0].id;
		}
	}

	async function handleToggleMcp(serverName: string, enabled: boolean) {
		if (!selected) return;
		const next = enabled
			? [...selected.mcp_servers, serverName]
			: selected.mcp_servers.filter((s) => s !== serverName);
		await updateSession(selected.id, { mcp_servers: next });
		await reload();
	}

	async function handleCreatePad(name: string) {
		try {
			await createScratchpad({ name });
			await reload();
		} catch (err) {
			$consoleError = String(err);
		}
	}

	async function handleToggleAttach(padId: string, attached: boolean) {
		if (!selected) return;
		const next = attached
			? [...selected.scratchpads, padId]
			: selected.scratchpads.filter((p) => p !== padId);
		await updateSession(selected.id, { scratchpads: next });
		await reload();
	}

	async function handleSavePad(padId: string, content: string) {
		await updateScratchpad(padId, { content });
		await reload();
	}

	async function handleDeletePad(padId: string) {
		await deleteScratchpad(padId);
		await reload();
	}
</script>

<div class="flex h-[calc(100vh-3.5rem)]">
	<SessionSidebar
		sessions={$consoleState.sessions}
		{selectedId}
		onSelect={(id) => (selectedId = id)}
		onCreate={handleCreate}
		onDelete={handleDelete}
	/>

	<section class="flex min-w-0 flex-1 flex-col">
		{#if $consoleLoading && $consoleState.sessions.length === 0}
			<div class="flex flex-1 items-center justify-center text-sm text-aptl-text-muted">
				Loading console…
			</div>
		{:else if $consoleError && $consoleState.sessions.length === 0}
			<div class="m-6 rounded-lg border border-aptl-red/20 bg-aptl-red/5 p-4 text-sm text-aptl-red">
				{$consoleError}
			</div>
		{:else if selected}
			<ChatPane session={selected} provider={$consoleState.provider} onTurnComplete={reload} />
		{:else}
			<div class="flex flex-1 flex-col items-center justify-center gap-2 text-center">
				<p class="text-sm text-aptl-text-muted">No session selected.</p>
				<p class="text-xs text-aptl-text-muted">
					Create a red or blue session from the left to start exploring APTL.
				</p>
			</div>
		{/if}
	</section>

	{#if selected}
		<aside class="w-72 shrink-0 overflow-y-auto border-l border-aptl-border bg-aptl-surface">
			<McpAccessPanel
				servers={$consoleState.servers}
				session={selected}
				onToggle={handleToggleMcp}
			/>
			<ScratchpadPanel
				scratchpads={$consoleState.scratchpads}
				session={selected}
				onCreate={handleCreatePad}
				onToggleAttach={handleToggleAttach}
				onSave={handleSavePad}
				onDelete={handleDeletePad}
			/>
		</aside>
	{/if}
</div>
