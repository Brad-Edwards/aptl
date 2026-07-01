<script lang="ts">
	// A declarative ACES experiment objective projected by the backend. Legacy
	// per-objective scoring, team, alert queries, and hints are not part of the
	// ACES objective shape; hint reveal (v1, local-only) belongs to a future
	// hints-bearing block, not this projection.
	interface Props {
		name: string;
		description: string;
		success: string;
	}

	let { name, description, success }: Props = $props();
</script>

<div class="rounded-lg border border-aptl-border bg-aptl-surface p-4">
	<div class="mb-2 flex flex-wrap items-center gap-2">
		<span class="rounded-full bg-aptl-indigo/10 px-2 py-0.5 text-xs font-medium text-aptl-indigo">
			objective
		</span>
		<span class="text-sm font-semibold text-aptl-text">{name}</span>
	</div>

	{#if description}
		<p class="text-sm text-aptl-text-muted">{description}</p>
	{/if}

	{#if success}
		<p class="mt-2 text-xs text-aptl-text-muted">
			<span class="font-medium text-aptl-text">Success:</span>
			{success}
		</p>
	{/if}
</div>
