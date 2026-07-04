import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Button from '../../../src/lib/components/kit/Button.svelte';
import { textSnippet } from './helpers';

describe('Button', () => {
	it('renders a <button> by default and applies the variant recipe', () => {
		const { container } = render(Button, {
			props: { variant: 'danger', children: textSnippet('Kill') }
		});
		const button = screen.getByRole('button', { name: 'Kill' });
		expect(button.tagName).toBe('BUTTON');
		expect(container.querySelector('button')?.className).toContain('bg-aptl-red');
	});

	it('renders an <a> when href is provided', () => {
		render(Button, { props: { href: '/terminal/victim', children: textSnippet('Terminal') } });
		const link = screen.getByRole('link', { name: 'Terminal' });
		expect(link.getAttribute('href')).toBe('/terminal/victim');
	});

	it('fires onclick', async () => {
		const onclick = vi.fn();
		render(Button, { props: { onclick, children: textSnippet('Go') } });
		await fireEvent.click(screen.getByRole('button', { name: 'Go' }));
		expect(onclick).toHaveBeenCalledOnce();
	});

	it('is disabled and unclickable when disabled', () => {
		render(Button, { props: { disabled: true, children: textSnippet('Start') } });
		expect((screen.getByRole('button', { name: 'Start' }) as HTMLButtonElement).disabled).toBe(true);
	});

	it('is inert when disabled and rendered as a link', async () => {
		const onclick = vi.fn();
		const { container } = render(Button, {
			props: { href: '/terminal/victim', disabled: true, onclick, children: textSnippet('Terminal') }
		});
		const link = container.querySelector('a') as HTMLAnchorElement;
		expect(link.getAttribute('href')).toBe(null);
		expect(link.getAttribute('aria-disabled')).toBe('true');
		expect(link.getAttribute('tabindex')).toBe('-1');
		await fireEvent.click(link);
		expect(onclick).not.toHaveBeenCalled();
	});

	it('uses the label prop as an accessible name for icon-only content', () => {
		render(Button, { props: { label: 'Refresh', children: textSnippet('⟳') } });
		expect(screen.getByRole('button', { name: 'Refresh' })).toBeTruthy();
	});
});
