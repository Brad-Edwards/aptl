<script lang="ts">
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import Terminal from '$lib/components/Terminal.svelte';
	import type { TerminalStatus } from '$lib/bff';
	import { guardControlledAction } from '$lib/stores/ui';
	import { preferences } from '$lib/stores/preferences';
	import { focusRing } from '$lib/components/kit/tone';

	const container = $derived($page.params.container ?? '');

	let status = $state<TerminalStatus | null>(null);
	// The PTY is not opened until the first-run local-use notice is acknowledged
	// (a UI precondition; the server still enforces every terminal gate).
	let launched = $state(false);

	// Re-enterable: also invoked from the placeholder's launch control, so a user
	// who dismisses the notice (Escape/backdrop) can retry without reloading.
	function launch(): void {
		guardControlledAction(() => (launched = true));
	}

	onMount(() => {
		launch();
	});

	// Short header label for the connection phase (the full, accessible status
	// text lives in the Terminal component's status region).
	const phaseLabel = $derived.by(() => {
		if (!launched) return 'awaiting acknowledgement';
		switch (status?.phase) {
			case 'connected':
				return 'connected';
			case 'error':
				return 'error';
			case 'closed':
				return 'closed';
			default:
				return 'connecting…';
		}
	});

	const phaseColor = $derived.by(() => {
		if (!launched) return 'text-aptl-amber';
		switch (status?.phase) {
			case 'connected':
				return 'text-aptl-green';
			case 'error':
				return 'text-aptl-red';
			case 'closed':
				return 'text-aptl-text-muted';
			default:
				return 'text-aptl-amber';
		}
	});
</script>

<div class="flex h-[calc(100vh-3.5rem)] flex-col">
	<div class="flex items-center gap-4 border-b border-aptl-border bg-aptl-surface px-6 py-3">
		<a
			href="/"
			class="text-sm text-aptl-indigo transition-colors hover:text-aptl-indigo-hover"
		>
			&larr; Back to Lab
		</a>
		<span class="text-sm text-aptl-text-muted">|</span>
		<h1 class="text-sm font-medium text-aptl-text">
			Terminal: <span class="font-mono text-aptl-indigo">{container}</span>
		</h1>
		<span class="ml-auto text-xs font-medium {phaseColor}">{phaseLabel}</span>
	</div>
	<div class="flex-1 overflow-hidden bg-[#1a1d23] p-1">
		{#if launched}
			<Terminal
				{container}
				fontSize={$preferences.terminalFontSize}
				scrollback={$preferences.terminalScrollback}
				onstatechange={(s) => (status = s)}
			/>
		{:else}
			<div class="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
				<p class="text-sm text-aptl-text-muted">
					Review and acknowledge the local-use notice to open the terminal.
				</p>
				<button
					type="button"
					onclick={launch}
					class="rounded-md border border-aptl-border bg-aptl-surface px-3 py-1.5 text-sm text-aptl-text hover:bg-aptl-surface-hover {focusRing}"
				>
					Open terminal
				</button>
			</div>
		{/if}
	</div>
</div>
