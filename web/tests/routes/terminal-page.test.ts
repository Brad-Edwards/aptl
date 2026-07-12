import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import { readable, get } from 'svelte/store';
import { resetPreferences, acknowledgeNotice } from '../../src/lib/stores/preferences';
import { noticeOpen } from '../../src/lib/stores/ui';

// The route reads the container from $app/stores' page store.
vi.mock('$app/stores', () => ({ page: readable({ params: { container: 'kali' } }) }));

// Stub heavy DOM-canvas dependencies that jsdom cannot handle (mirrors the
// Terminal component test).
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
vi.mock('@xterm/addon-fit', () => ({ FitAddon: vi.fn(() => ({ fit: vi.fn(), dispose: vi.fn() })) }));
vi.mock('@xterm/addon-web-links', () => ({ WebLinksAddon: vi.fn(() => ({ dispose: vi.fn() })) }));
vi.mock('@xterm/xterm/css/xterm.css', () => ({}));

beforeEach(() => {
	localStorage.clear();
	resetPreferences();
	noticeOpen.set(false);
	vi.stubGlobal(
		'fetch',
		vi.fn().mockResolvedValue({ ok: false, status: 503, text: () => Promise.resolve('') })
	);
	vi.stubGlobal(
		'WebSocket',
		vi.fn(function (this: Record<string, unknown>) {
			this.close = vi.fn();
			this.send = vi.fn();
		})
	);
	vi.stubGlobal('ResizeObserver', vi.fn(() => ({ observe: vi.fn(), disconnect: vi.fn() })));
});

afterEach(() => {
	vi.unstubAllGlobals();
});

async function renderTerminalPage() {
	const Page = (await import('../../src/routes/terminal/[container]/+page.svelte')).default;
	return render(Page);
}

describe('terminal route acknowledgement gate', () => {
	it('does not open the PTY until the local-use notice is acknowledged', async () => {
		await renderTerminalPage();
		expect(screen.getByText(/acknowledge the local-use notice/i)).toBeTruthy();
		// The Terminal component (and its status region) is not mounted yet.
		expect(screen.queryByRole('status')).toBeNull();
		// The guard opened the notice.
		expect(get(noticeOpen)).toBe(true);
	});

	it('opens the terminal immediately when already acknowledged', async () => {
		acknowledgeNotice();
		await renderTerminalPage();
		expect(screen.queryByText(/acknowledge the local-use notice/i)).toBeNull();
		// The Terminal component mounts and surfaces its connection status region.
		expect(screen.getByRole('status')).toBeTruthy();
	});

	it('is re-enterable: the placeholder launch control retries after a dismissal', async () => {
		await renderTerminalPage();
		// Notice was opened on mount; simulate the user dismissing it.
		noticeOpen.set(false);
		const launchButton = screen.getByRole('button', { name: /open terminal/i });

		// Re-triggering while still unacknowledged re-opens the notice (not stranded).
		await fireEvent.click(launchButton);
		expect(get(noticeOpen)).toBe(true);
		expect(screen.queryByRole('status')).toBeNull();

		// After acknowledging, the launch control opens the terminal.
		acknowledgeNotice();
		await fireEvent.click(screen.getByRole('button', { name: /open terminal/i }));
		expect(screen.getByRole('status')).toBeTruthy();
	});
});
