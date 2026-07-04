<script lang="ts">
	import { page } from '$app/stores';
	import Terminal from '$lib/components/Terminal.svelte';
	import type { TerminalStatus } from '$lib/bff';

	const container = $derived($page.params.container ?? '');

	let status = $state<TerminalStatus | null>(null);

	// Short header label for the connection phase (the full, accessible status
	// text lives in the Terminal component's status region).
	const phaseLabel = $derived.by(() => {
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
		<Terminal {container} onstatechange={(s) => (status = s)} />
	</div>
</div>
