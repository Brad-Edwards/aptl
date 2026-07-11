<script lang="ts">
	import Dialog from '$lib/components/kit/Dialog.svelte';
	import Button from '$lib/components/kit/Button.svelte';
	import { preferences, PREFERENCES_KEY } from '$lib/stores/preferences';
	import { formatTimestamp } from '$lib/time';

	interface Props {
		/** Open state. Bindable so the app shell can also close it. */
		open?: boolean;
		onClose?: () => void;
	}

	let { open = $bindable(false), onClose }: Props = $props();

	const ack = $derived($preferences.noticeAck);
	const acknowledgedAt = $derived(
		ack
			? formatTimestamp(ack.timestamp, {
					timeDisplay: $preferences.timeDisplay,
					locale: $preferences.locale
				})
			: null
	);
</script>

<Dialog
	bind:open
	title="Privacy"
	description="What this local operator surface stores and logs."
	{onClose}
>
	{#snippet body()}
		<div class="space-y-3">
			<p>
				APTL is a local lab operator tool, not a hosted service. It uses no non-essential
				analytics, tracking pixels, or third-party scripts in v1.
			</p>
			<ul class="list-disc space-y-1 pl-5 text-aptl-text-muted">
				<li>
					This browser stores only non-secret UI preferences, under the
					<code class="rounded bg-aptl-bg px-1 py-0.5 font-mono text-xs">{PREFERENCES_KEY}</code>
					key.
				</li>
				<li>It never stores API tokens, bearer headers, or service credentials.</li>
				<li>It does not persist terminal input or output in v1.</li>
				<li>
					Local API/server logs may record route names, timestamps, status codes, and redacted
					error categories — not request bodies or secrets.
				</li>
			</ul>
			{#if acknowledgedAt}
				<p class="text-xs text-aptl-text-muted">
					Local-use notice acknowledged {acknowledgedAt}.
				</p>
			{/if}
		</div>
	{/snippet}
	{#snippet footer()}
		<Button variant="primary" onclick={() => (open = false)}>Close</Button>
	{/snippet}
</Dialog>
