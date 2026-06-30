import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import TextInput from '../../../src/lib/components/kit/TextInput.svelte';
import TextInputHarness from './fixtures/TextInputHarness.svelte';

describe('TextInput', () => {
	it('renders with an accessible name and propagates typed value through bind:value', async () => {
		// Assert on the parent-owned bound value (surfaced via the harness), not the raw
		// DOM `input.value` — fireEvent sets that property directly, so reading it back
		// would be tautological and would stay green even if `bind:value` were dropped.
		render(TextInputHarness, { props: { ariaLabel: 'Custom query', value: '' } });
		const input = screen.getByRole('textbox', { name: 'Custom query' }) as HTMLInputElement;
		await fireEvent.input(input, { target: { value: 'rule.level:>=10' } });
		expect(screen.getByTestId('bound-value').textContent).toBe('rule.level:>=10');
	});

	it('reflects the invalid state on aria-invalid and border', () => {
		const { container } = render(TextInput, { props: { ariaLabel: 'Q', invalid: true } });
		const input = container.querySelector('input');
		expect(input?.getAttribute('aria-invalid')).toBe('true');
		expect(input?.className).toContain('border-aptl-red');
	});

	it('omits aria-invalid when valid', () => {
		const { container } = render(TextInput, { props: { ariaLabel: 'Q' } });
		expect(container.querySelector('input')?.getAttribute('aria-invalid')).toBeNull();
	});
});
