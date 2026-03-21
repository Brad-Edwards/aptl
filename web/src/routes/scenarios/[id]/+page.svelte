<script lang="ts">
	import type { ScenarioDefinition } from '$lib/types';
	import { buildBlockSequence } from '$lib/workbench';
	import WorkbenchStatusBar from '$lib/components/workbench/WorkbenchStatusBar.svelte';
	import NarrativeBlock from '$lib/components/workbench/NarrativeBlock.svelte';
	import ContainerStatusBlock from '$lib/components/workbench/ContainerStatusBlock.svelte';
	import AttackStepBlock from '$lib/components/workbench/AttackStepBlock.svelte';
	import SectionDivider from '$lib/components/workbench/SectionDivider.svelte';
	import ObjectiveBlock from '$lib/components/workbench/ObjectiveBlock.svelte';

	let { data }: { data: { scenario: ScenarioDefinition } } = $props();

	const blocks = $derived(buildBlockSequence(data.scenario));
</script>

<WorkbenchStatusBar scenario={data.scenario} />

<div class="mx-auto max-w-5xl space-y-6 px-6 py-8">
	{#each blocks as block (block.key)}
		{#if block.type === 'narrative'}
			<NarrativeBlock content={block.content} />
		{:else if block.type === 'container-status'}
			<ContainerStatusBlock containers={block.containers} />
		{:else if block.type === 'attack-step'}
			<AttackStepBlock step={block.step} stepIndex={block.stepIndex} />
		{:else if block.type === 'section-divider'}
			<SectionDivider title={block.title} />
		{:else if block.type === 'objective'}
			<ObjectiveBlock objective={block.objective} team={block.team} />
		{/if}
	{/each}
</div>
