<script lang="ts">
	// One ordered step projected from an ACES workflow. A display descriptor:
	// the workbench never auto-runs step content.
	interface Props {
		index: number;
		name: string;
		description: string;
		stepType: string;
	}

	let { index, name, description, stepType }: Props = $props();
</script>

<div class="rounded-lg border border-aptl-border bg-aptl-surface p-5">
	<div class="mb-2 flex flex-wrap items-start gap-3">
		<span
			class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-aptl-indigo text-xs font-bold text-white"
		>
			{index + 1}
		</span>
		<div class="flex-1">
			<h3 class="text-sm font-semibold text-aptl-text">{name}</h3>
			{#if stepType}
				<span class="mt-0.5 font-mono text-xs text-aptl-text-muted">{stepType}</span>
			{/if}
		</div>
	</div>

	{#if description}
		<p class="text-sm text-aptl-text-muted">{description}</p>
	{/if}
</div>
