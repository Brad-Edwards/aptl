<script lang="ts">
	import { page } from '$app/stores';
	import Terminal from '$lib/components/Terminal.svelte';

	const container = $derived($page.params.container ?? '');
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
	</div>
	<div class="flex-1 overflow-hidden bg-[#1a1d23] p-1">
		<Terminal {container} />
	</div>
</div>
