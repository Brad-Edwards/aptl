<script lang="ts">
	interface Props {
		running: boolean;
	}

	let { running }: Props = $props();
</script>

<div
	class="inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-medium
		{running
		? 'bg-aptl-green/10 text-aptl-green'
		: 'bg-aptl-text-muted/10 text-aptl-text-muted'}"
>
	<span
		class="h-2 w-2 rounded-full {running ? 'bg-aptl-green animate-pulse' : 'bg-aptl-text-muted'}"
	></span>
	{running ? 'Running' : 'Stopped'}
</div>
