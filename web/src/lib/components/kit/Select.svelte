<script lang="ts">
	import { getContext } from 'svelte';
	import { focusRing } from './tone';
	import { FIELD_CONTEXT_KEY, type FieldContext } from './field-context';

	interface SelectOption {
		value: string;
		label: string;
		disabled?: boolean;
	}

	interface Props {
		id?: string;
		value?: string;
		options: SelectOption[];
		disabled?: boolean;
		invalid?: boolean;
		describedById?: string;
		required?: boolean;
		/** Accessible name when no associated `Field`/`<label>` is present. */
		ariaLabel?: string;
	}

	let {
		id,
		value = $bindable(''),
		options,
		disabled = false,
		invalid,
		describedById,
		required,
		ariaLabel
	}: Props = $props();

	const field = getContext<FieldContext | undefined>(FIELD_CONTEXT_KEY);

	let resolvedId = $derived(id ?? field?.id);
	let resolvedInvalid = $derived(invalid ?? field?.invalid ?? false);
	let resolvedDescribedBy = $derived(describedById ?? field?.describedById);
	let resolvedRequired = $derived(required ?? field?.required ?? false);

	const base =
		'w-full rounded-md border bg-aptl-surface px-3 py-2 text-sm text-aptl-text disabled:cursor-not-allowed disabled:opacity-50';
	let cls = $derived(
		`${base} ${resolvedInvalid ? 'border-aptl-red' : 'border-aptl-border'} ${focusRing}`
	);
</script>

<select
	id={resolvedId}
	{disabled}
	required={resolvedRequired}
	aria-label={ariaLabel}
	aria-invalid={resolvedInvalid || undefined}
	aria-describedby={resolvedDescribedBy}
	class={cls}
	bind:value
>
	{#each options as option (option.value)}
		<option value={option.value} disabled={option.disabled}>{option.label}</option>
	{/each}
</select>
