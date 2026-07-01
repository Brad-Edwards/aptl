import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import LabStatusBadge from '../../src/lib/components/LabStatusBadge.svelte';

describe('LabStatusBadge', () => {
	it('shows a running status with a text label (not colour-only)', () => {
		render(LabStatusBadge, { props: { running: true } });
		const status = screen.getByRole('status', { name: 'Lab running' });
		expect(status.textContent).toContain('Lab running');
	});

	it('shows a stopped status with a text label', () => {
		render(LabStatusBadge, { props: { running: false } });
		const status = screen.getByRole('status', { name: 'Lab stopped' });
		expect(status.textContent).toContain('Lab stopped');
	});
});
