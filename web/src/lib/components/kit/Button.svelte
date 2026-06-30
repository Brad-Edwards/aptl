<script lang="ts">
	import type { Snippet } from 'svelte';
	import { buttonVariant, buttonSize, focusRing, type ButtonVariant, type ButtonSize } from './tone';

	interface Props {
		variant?: ButtonVariant;
		size?: ButtonSize;
		type?: 'button' | 'submit' | 'reset';
		/** When set, the button renders as a link (`<a>`). */
		href?: string;
		disabled?: boolean;
		/** Accessible name; required when the content is icon-only. */
		label?: string;
		onclick?: (event: MouseEvent) => void;
		children: Snippet;
	}

	let {
		variant = 'primary',
		size = 'md',
		type = 'button',
		href,
		disabled = false,
		label,
		onclick,
		children
	}: Props = $props();

	const base =
		'inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50';
	let cls = $derived(`${base} ${buttonSize[size]} ${buttonVariant[variant]} ${focusRing}`);

	function handleAnchorClick(event: MouseEvent) {
		if (disabled) {
			event.preventDefault();
			return;
		}
		onclick?.(event);
	}
</script>

{#if href}
	<a
		href={disabled ? undefined : href}
		class={cls}
		aria-label={label}
		aria-disabled={disabled || undefined}
		tabindex={disabled ? -1 : undefined}
		onclick={handleAnchorClick}
	>
		{@render children()}
	</a>
{:else}
	<button {type} class={cls} {disabled} aria-label={label} {onclick}>
		{@render children()}
	</button>
{/if}
