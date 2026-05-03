<script lang="ts">
	import type { Objective } from '$lib/types';
	import HintToggle from './HintToggle.svelte';
	import SiemQueryBlock from './SiemQueryBlock.svelte';

	interface Props {
		objective: Objective;
		team: 'red' | 'blue';
	}

	let { objective, team }: Props = $props();

	const borderClass = $derived(
		team === 'red' ? 'border-aptl-violet/30' : 'border-aptl-teal/30'
	);
	const badgeBg = $derived(
		team === 'red' ? 'bg-aptl-violet/10 text-aptl-violet' : 'bg-aptl-teal/10 text-aptl-teal'
	);
</script>

<div class="rounded-lg border {borderClass} bg-aptl-surface p-4">
	<div class="mb-2 flex flex-wrap items-center gap-2">
		<span class="rounded-full px-2 py-0.5 text-xs font-medium {badgeBg}">
			{team}
		</span>
		<span class="rounded-full bg-aptl-surface-hover px-2 py-0.5 text-xs text-aptl-text-muted">
			{objective.type}
		</span>
		<span class="ml-auto text-sm font-semibold text-aptl-text">
			{objective.points} pts
		</span>
	</div>

	<p class="text-sm text-aptl-text">{objective.description}</p>

	{#if objective.wazuh_alert}
		<div class="mt-3">
			<SiemQueryBlock
				query={objective.wazuh_alert.query}
				description={`Wazuh alert query (min ${objective.wazuh_alert.min_matches} match${objective.wazuh_alert.min_matches === 1 ? '' : 'es'} in ${objective.wazuh_alert.time_window_seconds}s)`}
				product_name="wazuh"
			/>
		</div>
	{/if}

	<HintToggle hints={objective.hints} objectiveId={objective.id} />
</div>
