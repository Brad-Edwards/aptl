<script lang="ts">
	import Dialog from '$lib/components/kit/Dialog.svelte';
	import Button from '$lib/components/kit/Button.svelte';
	import { focusRing } from '$lib/components/kit/tone';

	interface Props {
		/** Open state. Bindable so the parent can also close it. */
		open?: boolean;
		/** Disable the confirm control while a kill is already in flight. */
		pending?: boolean;
		/** Confirm handler — receives the chosen blast radius. */
		onConfirm: (containers: boolean) => void;
		/** Cancel handler (Cancel button, Escape, or backdrop). */
		onCancel?: () => void;
	}

	let { open = $bindable(false), pending = false, onConfirm, onCancel }: Props = $props();

	/** Blast-radius choice: when true, kill also force-stops every lab container. */
	let alsoStopContainers = $state(false);

	// Reset the choice each time the dialog opens, so a previous selection never
	// silently carries into the next confirmation.
	$effect(() => {
		if (open) alsoStopContainers = false;
	});

	function cancel(): void {
		onCancel?.();
	}

	function confirm(): void {
		onConfirm(alsoStopContainers);
	}
</script>

<Dialog
	bind:open
	title="Emergency kill"
	description="Immediately terminate all MCP server processes and clear scenario session state."
	onClose={cancel}
>
	{#snippet body()}
		<p>
			This stops every running MCP server process and clears the active scenario
			session and trace context. Running agent activity is terminated at once.
		</p>
		<label class="mt-4 flex items-start gap-2 {focusRing} rounded-md">
			<input
				type="checkbox"
				bind:checked={alsoStopContainers}
				class="mt-0.5 h-4 w-4 accent-aptl-red"
			/>
			<span>
				Also force-stop all lab containers
				<span class="mt-0.5 block text-xs text-aptl-text-muted">
					{alsoStopContainers
						? 'Blast radius: MCP processes and every lab container will be stopped.'
						: 'Blast radius: MCP processes only — lab containers keep running.'}
				</span>
			</span>
		</label>
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={cancel}>Cancel</Button>
		<Button variant="danger" disabled={pending} onclick={confirm}>
			{alsoStopContainers ? 'Kill + stop containers' : 'Kill processes'}
		</Button>
	{/snippet}
</Dialog>
