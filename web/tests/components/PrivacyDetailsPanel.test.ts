import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import PrivacyDetailsPanel from '../../src/lib/components/PrivacyDetailsPanel.svelte';
import { preferences, resetPreferences, PREFERENCES_KEY } from '../../src/lib/stores/preferences';

beforeEach(() => {
	localStorage.clear();
	resetPreferences();
});

describe('PrivacyDetailsPanel', () => {
	it('is not rendered when closed', () => {
		render(PrivacyDetailsPanel, { props: { open: false } });
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('states the no-analytics and no-token-storage posture and the storage key', async () => {
		render(PrivacyDetailsPanel, { props: { open: true } });
		await screen.findByRole('dialog');
		expect(screen.getByText(/no non-essential\s+analytics/i)).toBeTruthy();
		expect(screen.getByText(/never stores API tokens/i)).toBeTruthy();
		expect(screen.getByText(PREFERENCES_KEY)).toBeTruthy();
	});

	it('shows an acknowledgement time when the notice has been acknowledged', async () => {
		preferences.update((p) => ({
			...p,
			noticeAck: { version: '1', timestamp: '2026-01-02T03:04:05Z' }
		}));
		render(PrivacyDetailsPanel, { props: { open: true } });
		await screen.findByRole('dialog');
		expect(screen.getByText(/notice acknowledged/i)).toBeTruthy();
	});

	it('omits the acknowledgement line when never acknowledged', async () => {
		render(PrivacyDetailsPanel, { props: { open: true } });
		await screen.findByRole('dialog');
		expect(screen.queryByText(/notice acknowledged/i)).toBeNull();
	});
});
