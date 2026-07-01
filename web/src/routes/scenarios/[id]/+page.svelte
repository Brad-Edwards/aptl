<script lang="ts">
	import type { ScenarioDetail } from '$lib/types';
	import WorkbenchStatusBar from '$lib/components/workbench/WorkbenchStatusBar.svelte';
	import NarrativeBlock from '$lib/components/workbench/NarrativeBlock.svelte';
	import ContainerStatusBlock from '$lib/components/workbench/ContainerStatusBlock.svelte';
	import SectionDivider from '$lib/components/workbench/SectionDivider.svelte';
	import ObjectiveBlock from '$lib/components/workbench/ObjectiveBlock.svelte';
	import StepBlock from '$lib/components/workbench/StepBlock.svelte';
	import SiemQueryBlock from '$lib/components/workbench/SiemQueryBlock.svelte';
	import TerminalBlock from '$lib/components/workbench/TerminalBlock.svelte';

	let { data }: { data: { scenario: ScenarioDetail } } = $props();

	// Blocks are the backend-owned ordered projection; the route renders them
	// directly rather than deriving a sequence in the browser.
	const blocks = $derived(data.scenario.blocks);
</script>

<WorkbenchStatusBar scenario={data.scenario} />

<div class="mx-auto max-w-5xl space-y-6 px-6 py-8">
	{#each blocks as block (block.key)}
		{#if block.type === 'narrative'}
			<NarrativeBlock content={block.content} />
		{:else if block.type === 'container-status'}
			<ContainerStatusBlock containers={block.containers} />
		{:else if block.type === 'section-divider'}
			<SectionDivider title={block.title} />
		{:else if block.type === 'objective'}
			<ObjectiveBlock
				name={block.name}
				description={block.description}
				success={block.success}
			/>
		{:else if block.type === 'step'}
			<StepBlock
				index={block.index}
				name={block.name}
				description={block.description}
				stepType={block.step_type}
			/>
		{:else if block.type === 'siem-query'}
			<SiemQueryBlock
				query={block.query}
				description={block.description}
				product_name={block.product_name}
			/>
		{:else if block.type === 'terminal'}
			<TerminalBlock container={block.container} label={block.label} />
		{/if}
	{/each}
</div>
