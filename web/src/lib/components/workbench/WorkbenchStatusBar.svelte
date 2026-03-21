<script lang="ts">
	import type { ScenarioDefinition, ContainerInfo } from '$lib/types';
	import { labStatus } from '$lib/stores/lab';
	import { stateColor } from '$lib/container-state';

	interface Props {
		scenario: ScenarioDefinition;
	}

	let { scenario }: Props = $props();

	const meta = $derived(scenario.metadata);
	const containers = $derived(scenario.containers.required);

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

	function containerState(name: string): string {
		const c = $labStatus.containers.find((c: ContainerInfo) => c.name === name);
		return c?.state ?? 'unknown';
	}

	const totalPoints = $derived(
		scenario.objectives.red.reduce((sum, o) => sum + o.points, 0) +
			scenario.objectives.blue.reduce((sum, o) => sum + o.points, 0)
	);
</script>

<div
	class="sticky top-0 z-10 border-b border-aptl-border bg-aptl-bg/95 px-6 py-3 backdrop-blur-sm"
>
	<div class="mx-auto flex max-w-5xl items-center gap-4">
		<a
			href="/"
			class="text-xs text-aptl-text-muted transition-colors hover:text-aptl-text"
			aria-label="Back to Lab Home"
		>
			&larr; Lab
		</a>

		<h1 class="truncate text-sm font-semibold text-aptl-text">{meta.name}</h1>

		<span class="rounded-full px-2 py-0.5 text-xs font-medium {modeColor}">
			{scenario.mode}
		</span>

		<!-- Container pills -->
		<div class="flex items-center gap-1.5">
			{#each containers as name}
				{@const state = containerState(name)}
				<div
					class="flex items-center gap-1 rounded-full border border-aptl-border px-2 py-0.5"
					title="{name}: {state}"
				>
					<span
						class="inline-block h-1.5 w-1.5 rounded-full {stateColor(state)}"
						role="img"
						aria-label="{name} is {state}"
					></span>
					<span class="font-mono text-xs text-aptl-text-muted">{name}</span>
				</div>
			{/each}
		</div>

		<!-- Scoring -->
		{#if totalPoints > 0}
			<span class="ml-auto text-xs text-aptl-text-muted">
				{totalPoints} pts available
			</span>
		{/if}
	</div>
</div>
