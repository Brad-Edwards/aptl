<script lang="ts">
	import { untrack } from 'svelte';
	import Select from '../../../../src/lib/components/kit/Select.svelte';

	interface SelectOption {
		value: string;
		label: string;
		disabled?: boolean;
	}

	interface Props {
		ariaLabel?: string;
		options: SelectOption[];
		value?: string;
	}

	let { ariaLabel, options, value = '' }: Props = $props();
	// Seed the parent-owned bound value once; `bind:value` drives it thereafter.
	let bound = $state(untrack(() => value));
</script>

<Select {ariaLabel} {options} bind:value={bound} />
<span data-testid="bound-value">{bound}</span>
