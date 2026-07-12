import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import { get } from 'svelte/store';
import NavBar from '../../src/lib/components/NavBar.svelte';
import { settingsOpen, privacyOpen } from '../../src/lib/stores/ui';

beforeEach(() => {
	settingsOpen.set(false);
	privacyOpen.set(false);
});

describe('NavBar', () => {
	it('shows the Lab Home and Config nav links', () => {
		render(NavBar);
		expect(screen.getByRole('link', { name: 'Lab Home' })).toBeTruthy();
		expect(screen.getByRole('link', { name: 'Config' }).getAttribute('href')).toBe('/config');
	});

	it('opens Settings from the Settings button', async () => {
		render(NavBar);
		await fireEvent.click(screen.getByRole('button', { name: 'Settings' }));
		expect(get(settingsOpen)).toBe(true);
	});

	it('opens Privacy from the Help menu', async () => {
		render(NavBar);
		await fireEvent.click(screen.getByRole('button', { name: 'Help' }));
		await fireEvent.click(screen.getByRole('menuitem', { name: 'Privacy' }));
		expect(get(privacyOpen)).toBe(true);
	});
});
