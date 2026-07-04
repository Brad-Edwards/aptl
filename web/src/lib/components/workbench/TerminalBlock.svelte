<script lang="ts">
	import Terminal from '$lib/components/Terminal.svelte';

	interface Props {
		container: string;
		label?: string;
	}

	let { container, label }: Props = $props();

	const displayLabel = $derived(label ?? container);

	// Lazy tools stay lazy (UI-008d guardrail): the PTY WebSocket must not open
	// merely because the workbench document rendered. The embedded terminal is
	// mounted only after an explicit user action.
	let open = $state(false);
</script>

{#if open}
	<div class="overflow-hidden rounded-lg border border-aptl-border">
		<div class="flex items-center justify-between bg-aptl-surface px-3 py-2">
			<span class="font-mono text-xs text-aptl-text-muted">{displayLabel}</span>
			<a
				href="/terminal/{container}"
				class="text-xs text-aptl-indigo transition-colors hover:text-aptl-indigo-hover"
			>
				Maximize
			</a>
		</div>
		<div class="h-[300px]">
			<Terminal {container} />
		</div>
	</div>
{:else}
	<button
		onclick={() => (open = true)}
		class="flex w-full items-center justify-center gap-2 rounded-lg border border-dashed border-aptl-border py-3 text-xs text-aptl-text-muted transition-colors hover:border-aptl-indigo hover:text-aptl-indigo"
	>
		Open terminal: {displayLabel}
	</button>
{/if}
