<script lang="ts">
	import Badge from './Badge.svelte';
	import type { Tone } from './tone';

	interface Props {
		/** Semantic colour intent for the status. */
		tone?: Tone;
		/** Visible, non-colour status text (colour is never the only cue). */
		label: string;
		/** Animate the dot for live/running states. Honours reduced motion. */
		pulse?: boolean;
	}

	let { tone = 'neutral', label, pulse = false }: Props = $props();
</script>

<Badge {tone} dot {pulse} {label}>{label}</Badge>
