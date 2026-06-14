<script lang="ts">
	import type { ChatMessage } from '$lib/console/types';
	import { renderMarkdown } from '$lib/markdown';

	let { message }: { message: ChatMessage } = $props();

	const isUser = $derived(message.role === 'user');
</script>

<div class="flex {isUser ? 'justify-end' : 'justify-start'}">
	<div
		class="max-w-3xl rounded-lg px-4 py-2.5 {isUser
			? 'bg-aptl-indigo/15 text-aptl-text'
			: 'bg-aptl-surface text-aptl-text'}"
	>
		<div class="mb-1 text-xs font-medium uppercase tracking-wide text-aptl-text-muted">
			{message.role}
		</div>

		{#if message.content}
			<div class="prose-aptl text-sm">
				{@html renderMarkdown(message.content)}
			</div>
		{/if}

		{#each message.tool_calls as call (call.id)}
			<details class="mt-2 rounded border border-aptl-border bg-aptl-bg/50 text-xs">
				<summary class="cursor-pointer px-2 py-1 font-mono text-aptl-text-muted">
					<span class={call.is_error ? 'text-aptl-red' : 'text-aptl-teal'}>⚙</span>
					{call.name}
				</summary>
				<div class="border-t border-aptl-border px-2 py-1.5">
					<div class="mb-1 font-mono text-aptl-text-muted">
						input: {JSON.stringify(call.input)}
					</div>
					<pre class="whitespace-pre-wrap break-words font-mono {call.is_error
						? 'text-aptl-red'
						: 'text-aptl-text'}">{call.output}</pre>
				</div>
			</details>
		{/each}
	</div>
</div>
