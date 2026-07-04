import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import Menu from '../../../src/lib/components/kit/Menu.svelte';

function items() {
	return [
		{ label: 'Comfortable', onSelect: vi.fn() },
		{ label: 'Compact', onSelect: vi.fn(), disabled: true },
		{ label: 'Reset', onSelect: vi.fn() }
	];
}

describe('Menu', () => {
	it('renders a trigger with menu button semantics', () => {
		render(Menu, { props: { label: 'Density', items: items() } });
		const trigger = screen.getByRole('button', { name: 'Density' });
		expect(trigger.getAttribute('aria-haspopup')).toBe('menu');
		expect(trigger.getAttribute('aria-expanded')).toBe('false');
	});

	it('opens on click and focuses the first enabled item', async () => {
		render(Menu, { props: { label: 'Density', items: items() } });
		await fireEvent.click(screen.getByRole('button', { name: 'Density' }));
		const menu = screen.getByRole('menu', { name: 'Density' });
		expect(menu).toBeTruthy();
		await waitFor(() =>
			expect(document.activeElement).toBe(screen.getByRole('menuitem', { name: 'Comfortable' }))
		);
	});

	it('selects an item and closes, calling onSelect', async () => {
		const list = items();
		render(Menu, { props: { label: 'Density', items: list } });
		await fireEvent.click(screen.getByRole('button', { name: 'Density' }));
		await fireEvent.click(screen.getByRole('menuitem', { name: 'Reset' }));
		expect(list[2].onSelect).toHaveBeenCalledOnce();
		await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
	});

	it('skips the disabled item when navigating with ArrowDown', async () => {
		render(Menu, { props: { label: 'Density', items: items() } });
		const trigger = screen.getByRole('button', { name: 'Density' });
		await fireEvent.click(trigger);
		await fireEvent.keyDown(trigger, { key: 'ArrowDown' });
		await waitFor(() =>
			expect(document.activeElement).toBe(screen.getByRole('menuitem', { name: 'Reset' }))
		);
	});

	it('does not select a disabled item', async () => {
		const list = items();
		render(Menu, { props: { label: 'Density', items: list } });
		await fireEvent.click(screen.getByRole('button', { name: 'Density' }));
		await fireEvent.click(screen.getByRole('menuitem', { name: 'Compact' }));
		expect(list[1].onSelect).not.toHaveBeenCalled();
	});

	it('closes on Escape and restores focus to the trigger', async () => {
		render(Menu, { props: { label: 'Density', items: items() } });
		const trigger = screen.getByRole('button', { name: 'Density' });
		await fireEvent.click(trigger);
		await fireEvent.keyDown(trigger, { key: 'Escape' });
		await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
		expect(document.activeElement).toBe(trigger);
	});

	it('closes when clicking outside', async () => {
		render(Menu, { props: { label: 'Density', items: items() } });
		await fireEvent.click(screen.getByRole('button', { name: 'Density' }));
		expect(screen.getByRole('menu')).toBeTruthy();
		await fireEvent.click(document.body);
		await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
	});
});
