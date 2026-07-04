import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import StepBlock from '../../../src/lib/components/workbench/StepBlock.svelte';
import ObjectiveBlock from '../../../src/lib/components/workbench/ObjectiveBlock.svelte';
import TerminalBlock from '../../../src/lib/components/workbench/TerminalBlock.svelte';

// Stub the heavy DOM-canvas terminal deps jsdom cannot handle, so mounting the
// embedded terminal (on the lazy open action) exercises the {#if open} path
// without a real xterm instance.
vi.mock('@xterm/xterm', () => ({
	Terminal: vi.fn(() => ({
		loadAddon: vi.fn(),
		open: vi.fn(),
		onData: vi.fn(),
		onResize: vi.fn(),
		write: vi.fn(),
		dispose: vi.fn(),
		cols: 80,
		rows: 24
	}))
}));
vi.mock('@xterm/addon-fit', () => ({
	FitAddon: vi.fn(() => ({ fit: vi.fn(), dispose: vi.fn() }))
}));
vi.mock('@xterm/addon-web-links', () => ({
	WebLinksAddon: vi.fn(() => ({ dispose: vi.fn() }))
}));
vi.mock('@xterm/xterm/css/xterm.css', () => ({}));

beforeEach(() => {
	// Terminal.svelte fetches a short-lived ticket on mount; a rejecting stub
	// keeps that async path from touching the network in the unit test.
	vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('no network')));
	// jsdom lacks these browser DOM APIs the embedded terminal wires up on mount.
	vi.stubGlobal(
		'ResizeObserver',
		vi.fn(() => ({ observe: vi.fn(), unobserve: vi.fn(), disconnect: vi.fn() }))
	);
	vi.stubGlobal(
		'matchMedia',
		vi.fn(() => ({
			matches: false,
			addEventListener: vi.fn(),
			removeEventListener: vi.fn()
		}))
	);
});

describe('StepBlock', () => {
	it('renders a 1-based step number, name, type, and description', () => {
		render(StepBlock, {
			props: { index: 0, name: 'probe-portal', description: 'send the probe', stepType: 'action' }
		});
		expect(screen.getByText('1')).toBeTruthy();
		expect(screen.getByText('probe-portal')).toBeTruthy();
		expect(screen.getByText('action')).toBeTruthy();
		expect(screen.getByText('send the probe')).toBeTruthy();
	});
});

describe('ObjectiveBlock', () => {
	it('renders name, description, and the success summary', () => {
		render(ObjectiveBlock, {
			props: {
				name: 'demonstrate-handoff',
				description: 'bounded portal observation',
				success: 'all_of: metrics evidence-complete'
			}
		});
		expect(screen.getByText('demonstrate-handoff')).toBeTruthy();
		expect(screen.getByText('bounded portal observation')).toBeTruthy();
		expect(screen.getByText(/evidence-complete/)).toBeTruthy();
	});
});

describe('TerminalBlock (lazy)', () => {
	it('does not mount the terminal until the user opens it', async () => {
		render(TerminalBlock, { props: { container: 'kali', label: 'kali' } });

		// Before interaction: only the lazy affordance, no maximize link.
		const openBtn = screen.getByRole('button', { name: /Open terminal: kali/ });
		expect(screen.queryByText('Maximize')).toBeNull();

		await fireEvent.click(openBtn);

		// After the explicit action the embedded terminal mounts (maximize link).
		expect(screen.getByText('Maximize')).toBeTruthy();
	});
});
