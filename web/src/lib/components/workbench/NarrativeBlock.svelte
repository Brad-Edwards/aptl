<script lang="ts">
	import { renderMarkdown } from '$lib/markdown';

	interface Props {
		content: string;
	}

	let { content }: Props = $props();

	const html = $derived(renderMarkdown(content));
</script>

<div class="prose-aptl">
	{@html html}
</div>
