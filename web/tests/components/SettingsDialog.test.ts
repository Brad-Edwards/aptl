import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import { get } from 'svelte/store';
import SettingsDialog from '../../src/lib/components/SettingsDialog.svelte';
import {
	preferences,
	resetPreferences,
	DEFAULT_PREFERENCES
} from '../../src/lib/stores/preferences';

beforeEach(() => {
	localStorage.clear();
	resetPreferences();
});

describe('SettingsDialog', () => {
	it('is not rendered when closed', () => {
		render(SettingsDialog, { props: { open: false } });
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('renders an accessible drawer titled Settings', async () => {
		render(SettingsDialog, { props: { open: true } });
		const dialog = await screen.findByRole('dialog');
		const labelledBy = dialog.getAttribute('aria-labelledby');
		expect(document.getElementById(labelledBy!)?.textContent).toContain('Settings');
	});

	it('changing color mode updates and persists the preference', async () => {
		render(SettingsDialog, { props: { open: true } });
		const select = screen.getByLabelText('Color mode');
		await fireEvent.change(select, { target: { value: 'high-contrast' } });
		expect(get(preferences).colorMode).toBe('high-contrast');
	});

	it('changing density updates the preference', async () => {
		render(SettingsDialog, { props: { open: true } });
		await fireEvent.change(screen.getByLabelText('Density'), { target: { value: 'compact' } });
		expect(get(preferences).density).toBe('compact');
	});

	it('changing the SIEM row limit stores it as a number', async () => {
		render(SettingsDialog, { props: { open: true } });
		await fireEvent.change(screen.getByLabelText('Row limit'), { target: { value: '250' } });
		expect(get(preferences).siemRowLimit).toBe(250);
	});

	it('the font-size stepper increments within bounds', async () => {
		render(SettingsDialog, { props: { open: true } });
		await fireEvent.click(screen.getByRole('button', { name: /increase terminal font size/i }));
		expect(get(preferences).terminalFontSize).toBe(DEFAULT_PREFERENCES.terminalFontSize + 1);
	});

	it('reset returns preferences to defaults', async () => {
		render(SettingsDialog, { props: { open: true } });
		await fireEvent.change(screen.getByLabelText('Density'), { target: { value: 'compact' } });
		await fireEvent.click(screen.getByRole('button', { name: /reset preferences/i }));
		expect(get(preferences)).toEqual(DEFAULT_PREFERENCES);
	});
});
