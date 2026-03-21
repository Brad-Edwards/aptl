<script lang="ts">
	interface Props {
		query: Record<string, unknown>;
		description: string;
		product_name: string;
	}

	let { query, description, product_name }: Props = $props();

	const queryJson = $derived(JSON.stringify(query, null, 2));
</script>

<div class="rounded-lg border border-aptl-border bg-aptl-surface p-4">
	<div class="mb-2 flex items-center gap-2">
		<span class="rounded bg-aptl-teal/10 px-2 py-0.5 text-xs font-medium text-aptl-teal">
			{product_name}
		</span>
		<span class="text-xs text-aptl-text-muted">{description}</span>
	</div>
	<pre
		class="mb-3 overflow-x-auto rounded bg-aptl-bg p-3 font-mono text-xs text-aptl-text-muted">{queryJson}</pre>
	<div class="flex items-center gap-3">
		<button
			disabled
			class="rounded bg-aptl-teal/20 px-3 py-1.5 text-xs font-medium text-aptl-teal opacity-50 cursor-not-allowed"
		>
			Run Query
		</button>
		<span class="text-xs text-aptl-text-muted">OpenSearch integration coming soon</span>
	</div>
</div>
