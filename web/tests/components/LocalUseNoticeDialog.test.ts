import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import LocalUseNoticeDialog from '../../src/lib/components/LocalUseNoticeDialog.svelte';

function open(props: Record<string, unknown> = {}) {
	return render(LocalUseNoticeDialog, {
		props: { open: true, onAcknowledge: vi.fn(), ...props }
	});
}

describe('LocalUseNoticeDialog', () => {
	it('is not rendered when closed', () => {
		render(LocalUseNoticeDialog, { props: { open: false, onAcknowledge: vi.fn() } });
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('names the authorized local lab use title', async () => {
		open();
		const dialog = await screen.findByRole('dialog');
		const labelledBy = dialog.getAttribute('aria-labelledby');
		expect(document.getElementById(labelledBy!)?.textContent).toContain('Authorized local lab use');
	});

	it('states the no-token / no-terminal-persistence posture', () => {
		open();
		expect(screen.getByText(/does not store API tokens/i)).toBeTruthy();
	});

	it('acknowledge calls onAcknowledge', async () => {
		const onAcknowledge = vi.fn();
		open({ onAcknowledge });
		await fireEvent.click(screen.getByRole('button', { name: /acknowledge/i }));
		expect(onAcknowledge).toHaveBeenCalled();
	});

	it('cancels on Escape', async () => {
		const onCancel = vi.fn();
		open({ onCancel });
		const dialog = await screen.findByRole('dialog');
		await fireEvent.keyDown(dialog, { key: 'Escape' });
		await waitFor(() => expect(onCancel).toHaveBeenCalled());
	});

	it('exposes Privacy details only when a handler is provided', async () => {
		const onPrivacyDetails = vi.fn();
		open({ onPrivacyDetails });
		await fireEvent.click(screen.getByRole('button', { name: /privacy details/i }));
		expect(onPrivacyDetails).toHaveBeenCalled();
	});

	it('omits Privacy details when no handler is provided', () => {
		open();
		expect(screen.queryByRole('button', { name: /privacy details/i })).toBeNull();
	});
});
