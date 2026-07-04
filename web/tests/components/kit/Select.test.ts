import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Select from '../../../src/lib/components/kit/Select.svelte';
import SelectHarness from './fixtures/SelectHarness.svelte';

const OPTIONS = [
	{ value: '15m', label: 'Last 15 minutes' },
	{ value: '1h', label: 'Last hour' },
	{ value: '24h', label: 'Last 24 hours' }
];

describe('Select', () => {
	it('renders all options', () => {
		render(Select, { props: { ariaLabel: 'Time range', options: OPTIONS, value: '1h' } });
		expect(screen.getByRole('option', { name: 'Last 15 minutes' })).toBeTruthy();
		expect(screen.getAllByRole('option')).toHaveLength(3);
	});

	it('propagates the changed value through bind:value', async () => {
		// Assert on the parent-owned bound value (surfaced via the harness), not the raw
		// DOM `select.value` — fireEvent sets that property directly, so reading it back
		// would be tautological and would stay green even if `bind:value` were dropped.
		render(SelectHarness, { props: { ariaLabel: 'Time range', options: OPTIONS, value: '15m' } });
		const select = screen.getByRole('combobox', { name: 'Time range' }) as HTMLSelectElement;
		await fireEvent.change(select, { target: { value: '24h' } });
		expect(screen.getByTestId('bound-value').textContent).toBe('24h');
	});

	it('reflects the invalid state', () => {
		const { container } = render(Select, {
			props: { ariaLabel: 'T', options: OPTIONS, invalid: true }
		});
		expect(container.querySelector('select')?.getAttribute('aria-invalid')).toBe('true');
	});
});
