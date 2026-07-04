<script lang="ts">
	import type { Snippet } from 'svelte';
	import { toneSoft, toneDot, type Tone } from './tone';

	interface Props {
		/** Semantic colour intent. */
		tone?: Tone;
		/** Show a leading status dot. */
		dot?: boolean;
		/** Animate the dot (used for live/running states). Honours reduced motion. */
		pulse?: boolean;
		/**
		 * Accessible name. When set, the badge is exposed as `role="status"` so
		 * assistive tech announces it as a live status rather than inline text.
		 */
		label?: string;
		children: Snippet;
	}

	let { tone = 'neutral', dot = false, pulse = false, label, children }: Props = $props();
</script>

<span
	class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium {toneSoft[
		tone
	]}"
	role={label ? 'status' : undefined}
	aria-label={label}
>
	{#if dot}
		<span
			class="h-1.5 w-1.5 rounded-full {toneDot[tone]} {pulse ? 'motion-safe:animate-pulse' : ''}"
			aria-hidden="true"
		></span>
	{/if}
	{@render children()}
</span>
