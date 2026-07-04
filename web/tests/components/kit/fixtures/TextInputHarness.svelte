<script lang="ts">
	import { untrack } from 'svelte';
	import TextInput from '../../../../src/lib/components/kit/TextInput.svelte';

	interface Props {
		ariaLabel?: string;
		value?: string;
	}

	let { ariaLabel, value = '' }: Props = $props();
	// Seed the parent-owned bound value once; `bind:value` drives it thereafter.
	let bound = $state(untrack(() => value));
</script>

<TextInput {ariaLabel} bind:value={bound} />
<span data-testid="bound-value">{bound}</span>
