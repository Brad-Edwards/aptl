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
</script>

<a
	href="/scenarios/{scenario.id}"
	class="block rounded-lg border border-aptl-border bg-aptl-surface p-5 transition-colors hover:bg-aptl-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-aptl-focus focus-visible:ring-offset-2 focus-visible:ring-offset-aptl-bg"
>
	<div class="flex items-start justify-between gap-2">
		<h3 class="text-sm font-semibold text-aptl-text">{scenario.name}</h3>
		{#if !scenario.validation.valid}
			<span
				class="shrink-0 rounded-full bg-aptl-amber/10 px-2 py-0.5 text-xs font-medium text-aptl-amber"
			>
				unavailable
			</span>
		{/if}
	</div>

	{#if scenario.description}
		<p class="mt-1 line-clamp-3 text-xs text-aptl-text-muted">{scenario.description}</p>
	{/if}

	<div class="mt-3 flex flex-wrap items-center gap-2 text-xs">
		{#if scenario.mode}
			<span class="rounded-full px-2 py-0.5 font-medium {modeColor}">{scenario.mode}</span>
		{/if}
		{#if scenario.difficulty}
			<span class="text-aptl-text-muted">{scenario.difficulty}</span>
		{/if}
		{#if scenario.estimated_minutes}
			<span class="text-aptl-text-muted">~{scenario.estimated_minutes} min</span>
		{/if}
		{#if scenario.required_containers.length > 0}
			<span class="ml-auto font-mono text-aptl-text-muted">
				{scenario.required_containers.length} containers
			</span>
		{/if}
	</div>

	{#if scenario.tags.length > 0}
		<div class="mt-2 flex flex-wrap gap-1.5">
			{#each scenario.tags as tag (tag)}
				<span class="rounded bg-aptl-surface-hover px-1.5 py-0.5 text-xs text-aptl-text-muted">
					{tag}
				</span>
			{/each}
		</div>
	{/if}
</a>
