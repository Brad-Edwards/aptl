import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import StatusBadge from '../../../src/lib/components/kit/StatusBadge.svelte';

describe('StatusBadge', () => {
	it('shows a visible text label (colour is never the only cue)', () => {
		render(StatusBadge, { props: { tone: 'success', label: 'Running' } });
		const status = screen.getByRole('status', { name: 'Running' });
		expect(status.textContent).toContain('Running');
	});

	it('renders a status dot in the tone colour', () => {
		const { container } = render(StatusBadge, { props: { tone: 'neutral', label: 'Stopped' } });
		const dot = container.querySelector('span[aria-hidden="true"]');
		expect(dot?.className).toContain('bg-aptl-text-muted');
	});
});
