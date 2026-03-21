<script lang="ts">
	import type { Hint } from '$lib/types';

	interface Props {
		hints: Hint[];
		objectiveId: string;
	}

	let { hints, objectiveId }: Props = $props();

	let revealedCount = $state(0);

	const sortedHints = $derived([...hints].sort((a, b) => a.level - b.level));

	function revealNext() {
		if (revealedCount < sortedHints.length) {
			revealedCount++;
		}
	}
</script>

{#if sortedHints.length > 0}
	<div class="mt-3 space-y-2">
		{#each sortedHints as hint, i (hint.level)}
			{#if i < revealedCount}
				<div class="rounded border border-aptl-amber/20 bg-aptl-amber/5 px-3 py-2">
					<div class="flex items-center justify-between">
						<span class="text-xs font-medium text-aptl-amber">
							Hint {hint.level}
						</span>
						{#if hint.point_penalty > 0}
							<span class="text-xs text-aptl-amber">
								-{hint.point_penalty} pts
							</span>
						{/if}
					</div>
					<p class="mt-1 text-sm text-aptl-text">{hint.text}</p>
				</div>
			{/if}
		{/each}

		{#if revealedCount < sortedHints.length}
			{@const next = sortedHints[revealedCount]}
			<button
				onclick={revealNext}
				aria-label="Reveal hint {next.level} for objective {objectiveId}"
				class="text-xs text-aptl-amber transition-colors hover:text-aptl-text"
			>
				Show hint {next.level}
				{#if next.point_penalty > 0}
					<span class="text-aptl-text-muted">(-{next.point_penalty} pts)</span>
				{/if}
			</button>
		{/if}
	</div>
{/if}
