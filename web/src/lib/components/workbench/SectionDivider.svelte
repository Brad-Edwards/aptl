<script lang="ts">
	interface Props {
		title: string;
	}

	let { title }: Props = $props();
</script>

<div class="flex items-center gap-4 py-2">
	<div class="h-px flex-1 bg-aptl-border"></div>
	<span class="text-xs font-semibold uppercase tracking-wider text-aptl-text-muted">{title}</span>
	<div class="h-px flex-1 bg-aptl-border"></div>
</div>
