<script lang="ts">
	import type { ScenarioSummary } from '../types';

	interface Props {
		scenario: ScenarioSummary;
	}

	let { scenario }: Props = $props();

	const modeColor = $derived.by(() => {
		switch (scenario.mode) {
			case 'red':
				return 'bg-aptl-violet/10 text-aptl-violet';
			case 'blue':
				return 'bg-aptl-teal/10 text-aptl-teal';
			case 'purple':
				return 'bg-aptl-indigo/10 text-aptl-indigo';
			default:
				return 'bg-aptl-text-muted/10 text-aptl-text-muted';
		}
	});

	const difficultyColor = $derived.by(() => {
		switch (scenario.difficulty) {
			case 'beginner':
				return 'bg-aptl-green/10 text-aptl-green';
			case 'intermediate':
				return 'bg-aptl-amber/10 text-aptl-amber';
			case 'advanced':
				return 'bg-aptl-red/10 text-aptl-red';
			case 'expert':
				return 'bg-aptl-red/10 text-aptl-red';
			default:
				return 'bg-aptl-text-muted/10 text-aptl-text-muted';
		}
	});
</script>

<div
	class="rounded-lg border border-aptl-border bg-aptl-surface p-5 transition-colors hover:bg-aptl-surface-hover"
>
	<div class="mb-3 flex flex-wrap items-center gap-2">
		<span class="rounded-full px-2 py-0.5 text-xs font-medium {modeColor}">
			{scenario.mode}
		</span>
		<span class="rounded-full px-2 py-0.5 text-xs font-medium {difficultyColor}">
			{scenario.difficulty}
		</span>
	</div>

	<h3 class="text-sm font-semibold text-aptl-text">{scenario.name}</h3>
	<p class="mt-1 line-clamp-2 text-xs text-aptl-text-muted">{scenario.description}</p>

	<div class="mt-3 flex items-center gap-3 text-xs text-aptl-text-muted">
		<span>{scenario.estimated_minutes} min</span>
		{#if scenario.tags.length > 0}
			<span>&middot;</span>
			<span>{scenario.tags.slice(0, 3).join(', ')}</span>
		{/if}
	</div>

	{#if scenario.containers_required.length > 0}
		<div class="mt-3 flex flex-wrap gap-1">
			{#each scenario.containers_required as c}
				<span
					class="rounded bg-aptl-surface-hover px-1.5 py-0.5 font-mono text-xs text-aptl-text-muted"
				>
					{c}
				</span>
			{/each}
		</div>
	{/if}
</div>
