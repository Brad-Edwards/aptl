<script lang="ts">
	import type { AppConfig } from '$lib/types';
	import ConfigSummaryList from '$lib/components/ConfigSummaryList.svelte';

	let { data }: { data: { config: AppConfig | null; configError: boolean } } = $props();
</script>

<div class="mx-auto max-w-3xl space-y-6 px-6 py-8">
	<div>
		<h1 class="text-xl font-semibold text-aptl-text">Config</h1>
		<p class="mt-1 text-sm text-aptl-text-muted">
			Non-secret lab and web-serve settings. Read-only in v1.
		</p>
	</div>

	{#if data.configError || !data.config}
		<div
			class="rounded-lg border border-aptl-amber/20 bg-aptl-amber/5 p-8 text-center text-sm text-aptl-amber"
			role="status"
		>
			Configuration is currently unavailable.
		</div>
	{:else}
		<ConfigSummaryList config={data.config} />
	{/if}
</div>
