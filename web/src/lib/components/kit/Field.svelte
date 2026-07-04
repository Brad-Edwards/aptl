<script lang="ts">
	import type { Snippet } from 'svelte';
	import { setContext } from 'svelte';
	import { nextId } from './id';
	import { FIELD_CONTEXT_KEY, type FieldContext } from './field-context';

	interface Props {
		/** Visible label text, associated with the control via `for`/`id`. */
		label: string;
		/** Optional helper text wired as `aria-describedby`. */
		description?: string;
		/** Validation message; presence flips the control to the invalid state. */
		error?: string;
		required?: boolean;
		/** Override the generated control id. */
		id?: string;
		/** The form control(s); read field wiring from context. */
		children: Snippet;
	}

	let { label, description, error, required = false, id, children }: Props = $props();

	let baseId = $derived(id ?? nextId('aptl-field'));
	let descId = $derived(`${baseId}-desc`);
	let errId = $derived(`${baseId}-err`);

	let invalid = $derived(Boolean(error));
	let describedById = $derived(
		[description ? descId : null, error ? errId : null].filter(Boolean).join(' ') || undefined
	);

	const context: FieldContext = {
		get id() {
			return baseId;
		},
		get describedById() {
			return describedById;
		},
		get invalid() {
			return invalid;
		},
		get required() {
			return required;
		}
	};
	setContext(FIELD_CONTEXT_KEY, context);
</script>

<div class="flex flex-col gap-1">
	<label for={baseId} class="text-sm font-medium text-aptl-text">
		{label}{#if required}<span class="text-aptl-red" aria-hidden="true"> *</span>{/if}
	</label>
	{#if description}
		<p id={descId} class="text-xs text-aptl-text-muted">{description}</p>
	{/if}
	{@render children()}
	{#if error}
		<p id={errId} class="text-xs text-aptl-red" role="alert">{error}</p>
	{/if}
</div>
