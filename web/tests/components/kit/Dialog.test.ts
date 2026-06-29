import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import DialogHarness from './fixtures/DialogHarness.svelte';

async function open() {
	const result = render(DialogHarness, {});
	// Focus the trigger as a real keyboard/pointer interaction would, so the
	// dialog captures it as the element to restore focus to on close.
	const trigger = screen.getByTestId('trigger');
	trigger.focus();
	await fireEvent.click(trigger);
	const dialog = await screen.findByRole('dialog');
	return { ...result, dialog };
}

describe('Dialog', () => {
	it('is not in the DOM until opened', () => {
		render(DialogHarness, {});
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('exposes modal semantics and a programmatic name/description', async () => {
		const { dialog } = await open();
		expect(dialog.getAttribute('aria-modal')).toBe('true');
		const labelledBy = dialog.getAttribute('aria-labelledby');
		const describedBy = dialog.getAttribute('aria-describedby');
		expect(document.getElementById(labelledBy!)?.textContent).toContain('Confirm kill');
		expect(document.getElementById(describedBy!)?.textContent).toContain('Containers will stop.');
	});

	it('moves focus into the dialog when opened', async () => {
		const { dialog } = await open();
		expect(dialog.contains(document.activeElement)).toBe(true);
	});

	it('closes on Escape and returns focus to the trigger', async () => {
		const { dialog } = await open();
		await fireEvent.keyDown(dialog, { key: 'Escape' });
		await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
		expect(document.activeElement).toBe(screen.getByTestId('trigger'));
	});

	it('closes when the backdrop is clicked', async () => {
		await open();
		await fireEvent.click(screen.getByLabelText('Close dialog'));
		await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
	});

	it('invokes onClose when it closes', async () => {
		const onClose = vi.fn();
		render(DialogHarness, { props: { onClose } });
		await fireEvent.click(screen.getByTestId('trigger'));
		const dialog = await screen.findByRole('dialog');
		await fireEvent.keyDown(dialog, { key: 'Escape' });
		expect(onClose).toHaveBeenCalled();
	});

	it('supports a drawer placement', async () => {
		render(DialogHarness, { props: { placement: 'right' } });
		await fireEvent.click(screen.getByTestId('trigger'));
		const dialog = await screen.findByRole('dialog');
		expect(dialog.className).toContain('h-full');
	});
});
