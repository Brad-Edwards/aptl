import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import Badge from '../../../src/lib/components/kit/Badge.svelte';
import { textSnippet } from './helpers';

describe('Badge', () => {
	it('renders its content', () => {
		render(Badge, { props: { children: textSnippet('Ready') } });
		expect(screen.getByText('Ready')).toBeTruthy();
	});

	it('applies the soft recipe for the given tone', () => {
		const { container } = render(Badge, {
			props: { tone: 'success', children: textSnippet('Healthy') }
		});
		const badge = container.querySelector('span');
		expect(badge?.className).toContain('bg-aptl-green/10');
		expect(badge?.className).toContain('text-aptl-green');
	});

	it('renders a decorative dot when requested', () => {
		const { container } = render(Badge, {
			props: { tone: 'danger', dot: true, children: textSnippet('Down') }
		});
		const dot = container.querySelector('span > span[aria-hidden="true"]');
		expect(dot).toBeTruthy();
		expect(dot?.className).toContain('bg-aptl-red');
	});

	it('exposes role=status with an accessible name when label is set', () => {
		render(Badge, { props: { label: 'Lab running', children: textSnippet('Running') } });
		expect(screen.getByRole('status', { name: 'Lab running' })).toBeTruthy();
	});

	it('only animates the dot under motion-safe', () => {
		const { container } = render(Badge, {
			props: { tone: 'success', dot: true, pulse: true, children: textSnippet('Running') }
		});
		const dot = container.querySelector('span > span[aria-hidden="true"]');
		expect(dot?.className).toContain('motion-safe:animate-pulse');
	});
});
