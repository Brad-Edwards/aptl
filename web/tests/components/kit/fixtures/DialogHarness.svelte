<script lang="ts">
	import Dialog from '../../../../src/lib/components/kit/Dialog.svelte';

	interface Props {
		placement?: 'center' | 'right';
		onClose?: () => void;
	}

	let { placement = 'center', onClose }: Props = $props();
	let open = $state(false);
</script>

<button data-testid="trigger" onclick={() => (open = true)}>Open</button>

<Dialog bind:open title="Confirm kill" description="Containers will stop." {placement} {onClose}>
	{#snippet body()}
		<button data-testid="inner">Inner action</button>
	{/snippet}
	{#snippet footer()}
		<button data-testid="cancel" onclick={() => (open = false)}>Cancel</button>
	{/snippet}
</Dialog>
