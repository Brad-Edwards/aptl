<script lang="ts">
	import { focusRing } from './tone';
	import { nextId } from './id';

	interface MenuItem {
		label: string;
		onSelect: () => void;
		disabled?: boolean;
	}

	interface Props {
		/** Trigger text and the menu's accessible name. */
		label: string;
		items: MenuItem[];
		/** Horizontal alignment of the popup relative to the trigger. */
		align?: 'left' | 'right';
	}

	let { label, items, align = 'left' }: Props = $props();

	let open = $state(false);
	let activeIndex = $state(-1);
	let buttonEl = $state<HTMLButtonElement | null>(null);
	let menuEl = $state<HTMLDivElement | null>(null);

	const menuId = nextId('aptl-menu');

	function enabledIndexes(): number[] {
		return items.map((item, i) => (item.disabled ? -1 : i)).filter((i) => i >= 0);
	}

	function openMenu(focusLast = false): void {
		open = true;
		const enabled = enabledIndexes();
		activeIndex = enabled.length ? (focusLast ? enabled[enabled.length - 1] : enabled[0]) : -1;
	}

	function closeMenu(restoreFocus = true): void {
		open = false;
		activeIndex = -1;
		if (restoreFocus) buttonEl?.focus();
	}

	function moveActive(direction: 1 | -1): void {
		const enabled = enabledIndexes();
		if (!enabled.length) return;
		const pos = enabled.indexOf(activeIndex);
		activeIndex =
			pos === -1
				? direction === 1
					? enabled[0]
					: enabled[enabled.length - 1]
				: enabled[(pos + direction + enabled.length) % enabled.length];
	}

	function selectItem(index: number): void {
		const item = items[index];
		if (!item || item.disabled) return;
		item.onSelect();
		closeMenu();
	}

	function focusEdge(edge: 'first' | 'last'): boolean {
		const enabled = enabledIndexes();
		if (!enabled.length) return false;
		activeIndex = edge === 'first' ? enabled[0] : enabled[enabled.length - 1];
		return true;
	}

	function activateActive(): boolean {
		if (!open || activeIndex < 0) return false;
		selectItem(activeIndex);
		return true;
	}

	/**
	 * Key handlers, split into a dispatch table to keep each path simple. Each
	 * returns whether it handled the key, so the caller suppresses the default
	 * only when it acted — leaving the trigger's native Enter/Space activation
	 * intact while the menu is closed.
	 */
	const KEY_ACTIONS: Record<string, () => boolean> = {
		ArrowDown: () => (open ? moveActive(1) : openMenu(), true),
		ArrowUp: () => (open ? moveActive(-1) : openMenu(true), true),
		Home: () => open && focusEdge('first'),
		End: () => open && focusEdge('last'),
		Escape: () => (open ? (closeMenu(), true) : false),
		Enter: activateActive,
		' ': activateActive
	};

	function onKeydown(event: KeyboardEvent): void {
		if (KEY_ACTIONS[event.key]?.()) event.preventDefault();
	}

	function onWindowClick(event: MouseEvent): void {
		if (!open) return;
		const target = event.target as Node;
		if (buttonEl?.contains(target) || menuEl?.contains(target)) return;
		closeMenu(false);
	}

	$effect(() => {
		if (open && menuEl && activeIndex >= 0) {
			menuEl.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)?.focus();
		}
	});
</script>

<svelte:window onclick={onWindowClick} />

<div class="relative inline-block text-left">
	<button
		bind:this={buttonEl}
		type="button"
		aria-haspopup="menu"
		aria-expanded={open}
		aria-controls={open ? menuId : undefined}
		onclick={() => (open ? closeMenu() : openMenu())}
		onkeydown={onKeydown}
		class="inline-flex items-center gap-1 rounded-md border border-aptl-border bg-aptl-surface px-3 py-1.5 text-sm text-aptl-text hover:bg-aptl-surface-hover {focusRing}"
	>
		{label}
	</button>
	{#if open}
		<div
			bind:this={menuEl}
			id={menuId}
			role="menu"
			aria-label={label}
			tabindex="-1"
			onkeydown={onKeydown}
			class="absolute z-40 mt-1 min-w-[10rem] rounded-md border border-aptl-border bg-aptl-surface p-1 shadow-lg {align ===
			'right'
				? 'right-0'
				: 'left-0'}"
		>
			{#each items as item, index (item.label)}
				<button
					type="button"
					role="menuitem"
					data-index={index}
					tabindex="-1"
					disabled={item.disabled}
					onclick={() => selectItem(index)}
					class="block w-full rounded px-3 py-1.5 text-left text-sm text-aptl-text hover:bg-aptl-surface-hover disabled:cursor-not-allowed disabled:opacity-40 {focusRing}"
				>
					{item.label}
				</button>
			{/each}
		</div>
	{/if}
</div>
