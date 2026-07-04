<script lang="ts">
	import StatusBadge from '$lib/components/kit/StatusBadge.svelte';

	interface Props {
		running: boolean;
	}

	let { running }: Props = $props();
</script>

<!--
	Compact running/stopped status, built on the component-kit StatusBadge so the
	status palette and the live-pulse/reduced-motion behaviour stay centralised.
	Colour is never the only cue — the text label carries the state.
-->
<StatusBadge
	tone={running ? 'success' : 'neutral'}
	label={running ? 'Lab running' : 'Lab stopped'}
	pulse={running}
/>
