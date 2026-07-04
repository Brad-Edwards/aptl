<script lang="ts">
	import type { Snippet } from 'svelte';
	import { createFocusTrap, type FocusTrap } from './focus-trap';
	import { focusRing } from './tone';
	import { nextId } from './id';

	interface Props {
		/** Open state. Bindable so the parent can also close it. */
		open?: boolean;
		title: string;
		description?: string;
		/** `center` is a modal dialog; `right` is a side drawer. */
		placement?: 'center' | 'right';
		/** Called after the dialog closes (Escape, backdrop, or programmatic). */
		onClose?: () => void;
		body: Snippet;
		footer?: Snippet;
	}

	let {
		open = $bindable(false),
		title,
		description,
		placement = 'center',
		onClose,
		body,
		footer
	}: Props = $props();

	let dialogEl = $state<HTMLDivElement | null>(null);

	const titleId = nextId('aptl-dialog-title');
	const descId = nextId('aptl-dialog-desc');

	function close(): void {
		open = false;
		onClose?.();
	}

	function onKeydown(event: KeyboardEvent): void {
		if (event.key === 'Escape') {
			event.preventDefault();
			close();
		}
	}

	$effect(() => {
		if (!open || !dialogEl) return;
		const previouslyFocused = document.activeElement as HTMLElement | null;
		const trap: FocusTrap = createFocusTrap(dialogEl);
		trap.activate();
		dialogEl.focus();
		return () => {
			trap.deactivate();
			previouslyFocused?.focus?.();
		};
	});
</script>

{#if open}
	<div
		class="fixed inset-0 z-50 flex {placement === 'center'
			? 'items-center justify-center p-4'
			: 'justify-end'}"
	>
		<button
			type="button"
			class="absolute inset-0 cursor-default bg-black/60"
			aria-label="Close dialog"
			tabindex="-1"
			onclick={close}
		></button>
		<div
			bind:this={dialogEl}
			role="dialog"
			aria-modal="true"
			aria-labelledby={titleId}
			aria-describedby={description ? descId : undefined}
			tabindex="-1"
			onkeydown={onKeydown}
			class="relative border border-aptl-border bg-aptl-surface p-5 shadow-xl {placement ===
			'center'
				? 'w-full max-w-md rounded-lg'
				: 'h-full w-full max-w-sm'} {focusRing}"
		>
			<h2 id={titleId} class="text-base font-semibold text-aptl-text">{title}</h2>
			{#if description}
				<p id={descId} class="mt-1 text-sm text-aptl-text-muted">{description}</p>
			{/if}
			<div class="mt-4 text-sm text-aptl-text">{@render body()}</div>
			{#if footer}
				<div class="mt-5 flex justify-end gap-2">{@render footer()}</div>
			{/if}
		</div>
	</div>
{/if}
