<script lang="ts">
	import Dialog from '$lib/components/kit/Dialog.svelte';
	import Button from '$lib/components/kit/Button.svelte';

	interface Props {
		/** Open state. Bindable so the app shell can also close it. */
		open?: boolean;
		/** Acknowledge: record the notice version and run the deferred action. */
		onAcknowledge: () => void;
		/** Dismiss without acknowledging (Cancel, Escape, backdrop). */
		onCancel?: () => void;
		/** Open the persistent privacy details from within the notice. */
		onPrivacyDetails?: () => void;
	}

	let { open = $bindable(false), onAcknowledge, onCancel, onPrivacyDetails }: Props = $props();

	function cancel(): void {
		onCancel?.();
	}
</script>

<Dialog
	bind:open
	title="Authorized local lab use"
	description="APTL controls a local security lab. Use this surface only for authorized lab activity."
	onClose={cancel}
>
	{#snippet body()}
		<p>
			This browser stores local UI preferences. It does not store API tokens, and it does not
			persist terminal input or output in v1. Local API/server logs may record route names,
			timestamps, status codes, and redacted error categories.
		</p>
		<p class="mt-3 text-aptl-text-muted">
			Acknowledging records only the notice version and the time you acknowledged it.
		</p>
	{/snippet}
	{#snippet footer()}
		{#if onPrivacyDetails}
			<Button variant="secondary" onclick={onPrivacyDetails}>Privacy details</Button>
		{/if}
		<Button variant="primary" onclick={onAcknowledge}>Acknowledge</Button>
	{/snippet}
</Dialog>
