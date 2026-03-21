<script lang="ts">
	import { labStatus } from '$lib/stores/lab';
	import type { ContainerInfo } from '$lib/types';

	interface Props {
		containers: string[];
	}

	let { containers }: Props = $props();

	const filteredContainers = $derived.by(() => {
		const all: ContainerInfo[] = $labStatus.containers;
		const nameSet = new Set(containers);
		// Build a map: for containers present in store, use their data;
		// for missing ones, show as unknown
		return containers.map((name) => {
			const found = all.find((c) => c.name === name);
			if (found) return found;
			return { name, state: 'unknown', status: '', health: '', image: '', ports: [] };
		});
	});

	function stateColor(state: string): string {
		if (state === 'running') return 'bg-aptl-green';
		if (state === 'exited' || state === 'dead') return 'bg-aptl-red';
		return 'bg-aptl-amber';
	}
</script>

<div class="flex flex-wrap gap-2">
	{#each filteredContainers as c (c.name)}
		<div
			class="flex items-center gap-2 rounded-full border border-aptl-border bg-aptl-surface px-3 py-1.5"
		>
			<span
				class="inline-block h-2 w-2 rounded-full {stateColor(c.state)}"
				role="img"
				aria-label="{c.name} is {c.state}"
			></span>
			<span class="font-mono text-xs text-aptl-text">{c.name}</span>
		</div>
	{/each}
</div>
