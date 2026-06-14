<script lang="ts">
	import type { ChatMessage, ProviderStatus, Session, ToolCall } from '$lib/console/types';
	import { streamMessage } from '$lib/console/api';
	import MessageBubble from './MessageBubble.svelte';
	import RoleBadge from './RoleBadge.svelte';

	interface Props {
		session: Session;
		provider: ProviderStatus;
		onTurnComplete: () => void;
	}

	let { session, provider, onTurnComplete }: Props = $props();

	let input = $state('');
	let streaming = $state(false);
	let liveUser = $state<string | null>(null);
	let liveText = $state('');
	let liveTools = $state<ToolCall[]>([]);
	let notes = $state<string[]>([]);
	let error = $state<string | null>(null);
	let scroller: HTMLDivElement | null = $state(null);

	const liveAssistant = $derived<ChatMessage | null>(
		streaming || liveText || liveTools.length
			? {
					id: 'live',
					role: 'assistant',
					content: liveText,
					tool_calls: liveTools,
					created_at: 0
				}
			: null
	);

	function scrollDown() {
		queueMicrotask(() => scroller?.scrollTo({ top: scroller.scrollHeight }));
	}

	async function send() {
		const content = input.trim();
		if (!content || streaming) return;
		input = '';
		error = null;
		notes = [];
		liveUser = content;
		liveText = '';
		liveTools = [];
		streaming = true;
		scrollDown();

		try {
			await streamMessage(session.id, content, (event) => {
				switch (event.type) {
					case 'token':
						liveText += event.text;
						break;
					case 'tool_result':
						liveTools = [
							...liveTools,
							{
								id: event.id,
								name: event.name,
								input: {},
								output: event.output,
								is_error: event.is_error
							}
						];
						break;
					case 'note':
						notes = [...notes, event.message];
						break;
					case 'error':
						error = event.message;
						break;
				}
				scrollDown();
			});
		} catch (err) {
			error = String(err);
		} finally {
			streaming = false;
			liveUser = null;
			liveText = '';
			liveTools = [];
			onTurnComplete();
			scrollDown();
		}
	}

	function onKey(e: KeyboardEvent) {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			send();
		}
	}
</script>

<div class="flex h-full flex-col">
	<header class="flex items-center gap-2 border-b border-aptl-border px-4 py-3">
		<RoleBadge role={session.role} />
		<h2 class="truncate text-sm font-semibold text-aptl-text">{session.title}</h2>
		<span class="ml-auto text-xs {provider.live ? 'text-aptl-green' : 'text-aptl-amber'}">
			{provider.live ? `live · ${provider.model}` : 'demo mode'}
		</span>
	</header>

	<div bind:this={scroller} class="flex-1 space-y-3 overflow-y-auto px-4 py-4">
		{#if session.messages.length === 0 && !liveUser}
			<div class="rounded-lg border border-dashed border-aptl-border p-6 text-center text-sm text-aptl-text-muted">
				{#if provider.live}
					Start the conversation. This {session.role} session can use {session.mcp_servers.length}
					MCP server(s) and {session.scratchpads.length} scratchpad(s).
				{:else}
					Demo mode — no <code class="font-mono">ANTHROPIC_API_KEY</code>. Try
					<code class="font-mono">/help</code>, <code class="font-mono">/tools</code>, or
					<code class="font-mono">/run scratchpad_list {'{}'}</code>. Tools execute for real.
				{/if}
			</div>
		{/if}

		{#each session.messages as message (message.id)}
			<MessageBubble {message} />
		{/each}

		{#if liveUser}
			<MessageBubble
				message={{ id: 'live-user', role: 'user', content: liveUser, tool_calls: [], created_at: 0 }}
			/>
		{/if}

		{#each notes as note (note)}
			<div class="rounded-md border border-aptl-amber/20 bg-aptl-amber/5 px-3 py-1.5 text-xs text-aptl-amber">
				{note}
			</div>
		{/each}

		{#if liveAssistant}
			<MessageBubble message={liveAssistant} />
		{/if}

		{#if streaming && !liveText}
			<div class="px-1 text-xs text-aptl-text-muted">thinking…</div>
		{/if}

		{#if error}
			<div class="rounded-md border border-aptl-red/20 bg-aptl-red/5 px-3 py-1.5 text-xs text-aptl-red">
				{error}
			</div>
		{/if}
	</div>

	<div class="border-t border-aptl-border p-3">
		<div class="flex items-end gap-2">
			<textarea
				bind:value={input}
				onkeydown={onKey}
				rows="2"
				placeholder={provider.live ? 'Message the agent…' : 'Demo mode — try /help'}
				disabled={streaming}
				class="min-w-0 flex-1 resize-none rounded-md border border-aptl-border bg-aptl-bg px-3 py-2 text-sm text-aptl-text placeholder:text-aptl-text-muted focus:border-aptl-indigo focus:outline-none disabled:opacity-50"
			></textarea>
			<button
				onclick={send}
				disabled={streaming || !input.trim()}
				class="rounded-md bg-aptl-indigo px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-aptl-indigo-hover disabled:opacity-50"
			>
				{streaming ? '…' : 'Send'}
			</button>
		</div>
	</div>
</div>
