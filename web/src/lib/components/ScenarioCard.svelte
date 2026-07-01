<script lang="ts">
	import type { ScenarioSummary } from '../types';

	interface Props {
		scenario: ScenarioSummary;
	}

	let { scenario }: Props = $props();
</script>

<a
	href="/scenarios/{scenario.id}"
	class="block rounded-lg border border-aptl-border bg-aptl-surface p-5 transition-colors hover:bg-aptl-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-aptl-focus focus-visible:ring-offset-2 focus-visible:ring-offset-aptl-bg"
>
	<h3 class="text-sm font-semibold text-aptl-text">{scenario.name}</h3>
	{#if scenario.description}
		<p class="mt-1 line-clamp-3 text-xs text-aptl-text-muted">{scenario.description}</p>
	{/if}
</a>
