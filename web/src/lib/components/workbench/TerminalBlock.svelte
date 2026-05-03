<script lang="ts">
	import Terminal from '$lib/components/Terminal.svelte';

	interface Props {
		container: string;
		label?: string;
	}

	let { container, label }: Props = $props();

	const displayLabel = $derived(label ?? container);
</script>

<div class="overflow-hidden rounded-lg border border-aptl-border">
	<div class="flex items-center justify-between bg-aptl-surface px-3 py-2">
		<span class="font-mono text-xs text-aptl-text-muted">{displayLabel}</span>
		<a
			href="/terminal/{container}"
			class="text-xs text-aptl-indigo transition-colors hover:text-aptl-indigo-hover"
		>
			Maximize
		</a>
	</div>
	<div class="h-[300px]">
		<Terminal {container} />
	</div>
</div>
