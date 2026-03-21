<script lang="ts">
	import type { ContainerInfo } from '../types';
	import ContainerCard from './ContainerCard.svelte';

	interface Props {
		containers: ContainerInfo[];
	}

	let { containers }: Props = $props();
</script>

{#if containers.length === 0}
	<div class="rounded-lg border border-dashed border-aptl-border p-8 text-center">
		<p class="text-sm text-aptl-text-muted">No containers running</p>
	</div>
{:else}
	<div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
		{#each containers as container (container.name)}
			<ContainerCard {container} />
		{/each}
	</div>
{/if}
