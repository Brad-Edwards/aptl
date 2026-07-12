import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import { writable, get } from 'svelte/store';

// The layout initialises the lab store on mount; stub it so no fetch/SSE runs.
vi.mock('$lib/stores/lab', () => ({
	initLabStore: vi.fn(),
	destroyLabStore: vi.fn(),
	labStatus: writable({ running: false, containers: [], error: null })
}));

import LayoutHarness from './fixtures/LayoutHarness.svelte';
import { privacyOpen } from '../../src/lib/stores/ui';

beforeEach(() => {
	localStorage.clear();
	privacyOpen.set(false);
});

describe('app shell layout', () => {
	it('renders route children and a persistent Privacy link', () => {
		render(LayoutHarness);
		expect(screen.getByText('child content')).toBeTruthy();
		expect(screen.getByRole('button', { name: 'Privacy' })).toBeTruthy();
	});

	it('opens the privacy panel from the footer Privacy link', async () => {
		render(LayoutHarness);
		await fireEvent.click(screen.getByRole('button', { name: 'Privacy' }));
		expect(get(privacyOpen)).toBe(true);
	});
});
