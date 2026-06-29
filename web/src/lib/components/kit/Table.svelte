<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { Density } from './tone';

	interface Props {
		/** Required table caption (WCAG: tables need a programmatic name). */
		caption: string;
		/** Render the caption visibly; otherwise it is screen-reader-only. */
		captionVisible?: boolean;
		/** Cell padding density. */
		density?: Density;
		/** `<tr>`/`<th>` markup for the header row. */
		head: Snippet;
		/** `<tr>`/`<td>` markup for the body rows. */
		body: Snippet;
	}

	let { caption, captionVisible = false, density = 'comfortable', head, body }: Props = $props();
</script>

<table class="aptl-table density-{density} w-full border-collapse text-sm">
	<caption
		class={captionVisible
			? 'mb-2 text-left text-sm font-medium text-aptl-text'
			: 'sr-only'}
	>
		{caption}
	</caption>
	<thead class="border-b border-aptl-border text-left text-xs font-medium text-aptl-text-muted">
		{@render head()}
	</thead>
	<tbody class="divide-y divide-aptl-border text-aptl-text">
		{@render body()}
	</tbody>
</table>

<style>
	/* Density controls cell padding for plain <th>/<td> in the slotted markup,
	   so consumers write semantic table rows without repeating padding classes. */
	.aptl-table.density-comfortable :global(th),
	.aptl-table.density-comfortable :global(td) {
		padding: 0.625rem 1rem;
	}
	.aptl-table.density-compact :global(th),
	.aptl-table.density-compact :global(td) {
		padding: 0.375rem 0.75rem;
	}
</style>
