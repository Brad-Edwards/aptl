import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import KillConfirmDialog from '../../src/lib/components/KillConfirmDialog.svelte';

function open(props: Record<string, unknown> = {}) {
	return render(KillConfirmDialog, {
		props: { open: true, onConfirm: vi.fn(), ...props }
	});
}

describe('KillConfirmDialog', () => {
	it('is not rendered when closed', () => {
		render(KillConfirmDialog, { props: { open: false, onConfirm: vi.fn() } });
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('exposes an accessible modal dialog with a title', async () => {
		open();
		const dialog = await screen.findByRole('dialog');
		expect(dialog.getAttribute('aria-modal')).toBe('true');
		const labelledBy = dialog.getAttribute('aria-labelledby');
		expect(document.getElementById(labelledBy!)?.textContent).toContain('Emergency kill');
	});

	it('defaults to processes-only and names that blast radius', () => {
		open();
		expect(screen.getByText(/lab containers keep running/i)).toBeTruthy();
		expect(screen.getByRole('button', { name: /kill processes/i })).toBeTruthy();
	});

	it('widens the blast-radius copy and button when containers are toggled on', async () => {
		open();
		const checkbox = screen.getByRole('checkbox', {
			name: /also force-stop all lab containers/i
		});
		await fireEvent.click(checkbox);
		expect(screen.getByText(/every lab container will be stopped/i)).toBeTruthy();
		expect(screen.getByRole('button', { name: /kill \+ stop containers/i })).toBeTruthy();
	});

	it('confirms with containers=false by default', async () => {
		const onConfirm = vi.fn();
		open({ onConfirm });
		await fireEvent.click(screen.getByRole('button', { name: /kill processes/i }));
		expect(onConfirm).toHaveBeenCalledWith(false);
	});

	it('confirms with containers=true when toggled on', async () => {
		const onConfirm = vi.fn();
		open({ onConfirm });
		await fireEvent.click(
			screen.getByRole('checkbox', { name: /also force-stop all lab containers/i })
		);
		await fireEvent.click(screen.getByRole('button', { name: /kill \+ stop containers/i }));
		expect(onConfirm).toHaveBeenCalledWith(true);
	});

	it('cancels via the Cancel button without confirming', async () => {
		const onConfirm = vi.fn();
		const onCancel = vi.fn();
		open({ onConfirm, onCancel });
		await fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
		expect(onCancel).toHaveBeenCalled();
		expect(onConfirm).not.toHaveBeenCalled();
	});

	it('cancels on Escape', async () => {
		const onCancel = vi.fn();
		open({ onCancel });
		const dialog = await screen.findByRole('dialog');
		await fireEvent.keyDown(dialog, { key: 'Escape' });
		await waitFor(() => expect(onCancel).toHaveBeenCalled());
	});

	it('disables confirm while a kill is pending', () => {
		open({ pending: true });
		expect(
			(screen.getByRole('button', { name: /kill processes/i }) as HTMLButtonElement).disabled
		).toBe(true);
	});
});
