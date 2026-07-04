import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import FieldHarness from './fixtures/FieldHarness.svelte';

describe('Field', () => {
	it('associates the label with the control via for/id', () => {
		render(FieldHarness, { props: { label: 'Scenario name' } });
		const input = screen.getByLabelText('Scenario name');
		expect(input.tagName).toBe('INPUT');
		expect(input.id).toBeTruthy();
	});

	it('wires the description through aria-describedby', () => {
		render(FieldHarness, {
			props: { label: 'Time range', description: 'Backend still enforces the maximum.' }
		});
		const input = screen.getByLabelText('Time range');
		const describedBy = input.getAttribute('aria-describedby');
		expect(describedBy).toBeTruthy();
		const desc = document.getElementById(describedBy!.split(' ')[0]);
		expect(desc?.textContent).toContain('Backend still enforces');
	});

	it('marks the control invalid and exposes the error as an alert', () => {
		render(FieldHarness, { props: { label: 'Row limit', error: 'Above the backend cap.' } });
		const input = screen.getByLabelText('Row limit');
		expect(input.getAttribute('aria-invalid')).toBe('true');
		const alert = screen.getByRole('alert');
		expect(alert.textContent).toContain('Above the backend cap.');
		expect(input.getAttribute('aria-describedby')).toContain(alert.id);
	});

	it('propagates required to the control', () => {
		render(FieldHarness, { props: { label: 'Query', required: true } });
		expect((screen.getByLabelText(/Query/) as HTMLInputElement).required).toBe(true);
	});
});
