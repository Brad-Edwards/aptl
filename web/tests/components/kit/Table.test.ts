import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import TableHarness from './fixtures/TableHarness.svelte';

describe('Table', () => {
	it('renders a captioned table with header and body cells', () => {
		render(TableHarness, {});
		const table = screen.getByRole('table', { name: 'Recent alerts' });
		expect(table).toBeTruthy();
		expect(screen.getByRole('columnheader', { name: 'Rule' })).toBeTruthy();
		expect(screen.getByRole('cell', { name: 'auth-fail' })).toBeTruthy();
	});

	it('keeps the caption screen-reader-only by default', () => {
		const { container } = render(TableHarness, {});
		expect(container.querySelector('caption')?.className).toContain('sr-only');
	});

	it('renders the caption visibly when requested', () => {
		const { container } = render(TableHarness, { props: { captionVisible: true } });
		expect(container.querySelector('caption')?.className).not.toContain('sr-only');
	});

	it('applies the density class', () => {
		const { container } = render(TableHarness, { props: { density: 'compact' } });
		expect(container.querySelector('table')?.className).toContain('density-compact');
	});
});
