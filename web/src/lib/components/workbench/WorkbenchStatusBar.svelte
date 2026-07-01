<script lang="ts">
	import type { ScenarioDetail, ContainerInfo } from '$lib/types';
	import { labStatus } from '$lib/stores/lab';
	import { stateColor } from '$lib/container-state';

	interface Props {
		scenario: ScenarioDetail;
	}

	let { scenario }: Props = $props();

	const containers = $derived(scenario.required_containers);

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

		<h1 class="truncate text-sm font-semibold text-aptl-text">{scenario.name}</h1>

		{#if scenario.mode}
			<span class="rounded-full px-2 py-0.5 text-xs font-medium {modeColor}">
				{scenario.mode}
			</span>
		{/if}

		{#if scenario.difficulty}
			<span class="text-xs text-aptl-text-muted">{scenario.difficulty}</span>
		{/if}

		{#if scenario.estimated_minutes}
			<span class="text-xs text-aptl-text-muted">~{scenario.estimated_minutes} min</span>
		{/if}

		<!-- Container pills -->
		<div class="flex items-center gap-1.5">
			{#each containers as name (name)}
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

		<!-- Scenario projection validity (distinct from lab readiness) -->
		{#if !scenario.validation.valid}
			<span
				class="ml-auto rounded-full bg-aptl-amber/10 px-2 py-0.5 text-xs font-medium text-aptl-amber"
				role="status"
			>
				{scenario.validation.detail ?? 'Scenario unavailable'}
			</span>
		{/if}
	</div>
</div>
