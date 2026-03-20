<script lang="ts">
	import { labStatus, labLoading } from '$lib/stores/lab';
	import { startLab, stopLab } from '$lib/api';
	import ContainerGrid from '$lib/components/ContainerGrid.svelte';
	import ScenarioCard from '$lib/components/ScenarioCard.svelte';
	import type { ScenarioSummary } from '$lib/types';

	let { data }: { data: { scenarios: ScenarioSummary[] } } = $props();

	let actionPending = $state(false);
	let actionError = $state('');

	async function handleStart() {
		actionPending = true;
		actionError = '';
		try {
			const result = await startLab();
			if (!result.success) {
				actionError = result.error || 'Lab start failed';
			}
		} catch (err) {
			actionError = String(err);
		} finally {
			actionPending = false;
		}
	}

	async function handleStop() {
		actionPending = true;
		actionError = '';
		try {
			const result = await stopLab();
			if (!result.success) {
				actionError = result.error || 'Lab stop failed';
			}
		} catch (err) {
			actionError = String(err);
		} finally {
			actionPending = false;
		}
	}
</script>

<div class="mx-auto max-w-7xl space-y-8 px-6 py-8">
	<!-- Lab Status Section -->
	<section>
		<div class="mb-4 flex items-center justify-between">
			<div>
				<h1 class="text-xl font-semibold text-aptl-text">Lab Home</h1>
				<p class="mt-1 text-sm text-aptl-text-muted">
					{$labStatus.running
						? `${$labStatus.containers.length} containers running`
						: 'Lab is stopped'}
				</p>
			</div>
			<div class="flex items-center gap-3">
				{#if $labStatus.running}
					<button
						onclick={handleStop}
						disabled={actionPending}
						class="rounded-lg bg-aptl-red/10 px-4 py-2 text-sm font-medium text-aptl-red transition-colors hover:bg-aptl-red/20 disabled:opacity-50"
					>
						{actionPending ? 'Stopping...' : 'Stop Lab'}
					</button>
				{:else}
					<button
						onclick={handleStart}
						disabled={actionPending}
						class="rounded-lg bg-aptl-indigo px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-aptl-indigo-hover disabled:opacity-50"
					>
						{actionPending ? 'Starting...' : 'Start Lab'}
					</button>
				{/if}
			</div>
		</div>

		{#if actionError}
			<div
				class="mb-4 rounded-lg border border-aptl-red/20 bg-aptl-red/5 p-3 text-sm text-aptl-red"
			>
				{actionError}
			</div>
		{/if}

		{#if $labStatus.error && !actionError}
			<div
				class="mb-4 rounded-lg border border-aptl-amber/20 bg-aptl-amber/5 p-3 text-sm text-aptl-amber"
			>
				{$labStatus.error}
			</div>
		{/if}

		{#if $labLoading}
			<div class="flex items-center justify-center py-12">
				<div
					class="h-8 w-8 animate-spin rounded-full border-2 border-aptl-indigo border-t-transparent"
				></div>
			</div>
		{:else}
			<ContainerGrid containers={$labStatus.containers} />
		{/if}
	</section>

	<!-- Scenarios Section -->
	<section>
		<div class="mb-4">
			<h2 class="text-lg font-semibold text-aptl-text">Scenarios</h2>
			<p class="mt-1 text-sm text-aptl-text-muted">
				Available attack and defense scenarios
			</p>
		</div>

		{#if data.scenarios.length === 0}
			<div class="rounded-lg border border-dashed border-aptl-border p-8 text-center">
				<p class="text-sm text-aptl-text-muted">No scenarios found</p>
			</div>
		{:else}
			<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
				{#each data.scenarios as scenario (scenario.id)}
					<ScenarioCard {scenario} />
				{/each}
			</div>
		{/if}
	</section>
</div>
