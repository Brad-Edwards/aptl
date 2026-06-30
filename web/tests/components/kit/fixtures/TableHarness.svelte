<script lang="ts">
	import Table from '../../../../src/lib/components/kit/Table.svelte';
	import type { Density } from '../../../../src/lib/components/kit/tone';

	interface Props {
		density?: Density;
		captionVisible?: boolean;
	}

	let { density = 'comfortable', captionVisible = false }: Props = $props();
</script>

<Table caption="Recent alerts" {density} {captionVisible}>
	{#snippet head()}
		<tr><th>Rule</th><th>Host</th></tr>
	{/snippet}
	{#snippet body()}
		<tr><td>auth-fail</td><td>victim</td></tr>
	{/snippet}
</Table>
