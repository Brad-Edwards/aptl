import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { writable } from 'svelte/store';
import type { LabStatus } from '../../src/lib/types';

const labStatus = writable<LabStatus>({ running: false, containers: [], error: null });
const labLoading = writable(false);
const refreshLabStatus = vi.fn().mockResolvedValue(undefined);
const startLab = vi.fn();
const stopLab = vi.fn();
const killLab = vi.fn();

vi.mock('$lib/stores/lab', () => ({ labStatus, labLoading, refreshLabStatus }));
vi.mock('$lib/api', () => ({ startLab, stopLab, killLab }));

async function renderPage(
	data: { scenarios: { id: string; name: string; description: string }[]; scenariosError: boolean } = {
		scenarios: [],
		scenariosError: false
	}
) {
	const Page = (await import('../../src/routes/+page.svelte')).default;
	return render(Page, { props: { data } });
}

describe('Lab Home route', () => {
	beforeEach(() => {
		labStatus.set({ running: false, containers: [], error: null });
		labLoading.set(false);
		vi.clearAllMocks();
		refreshLabStatus.mockResolvedValue(undefined);
	});

	it('leads with a stopped readiness headline and a Start control', async () => {
		await renderPage();
		expect(screen.getByRole('status', { name: 'Lab stopped' })).toBeTruthy();
		expect(screen.getByRole('button', { name: 'Start' })).toBeTruthy();
		expect(screen.queryByRole('button', { name: 'Stop' })).toBeNull();
	});

	it('shows a running readiness headline and a Stop control when running', async () => {
		labStatus.set({ running: true, containers: [], error: null });
		await renderPage();
		expect(screen.getByRole('status', { name: 'Lab running' })).toBeTruthy();
		expect(screen.getByRole('button', { name: 'Stop' })).toBeTruthy();
	});

	it('serializes lifecycle actions (single-flight) and renders ADR-030 start diagnostics', async () => {
		let resolveStart: (v: unknown) => void = () => {};
		startLab.mockReturnValue(new Promise((r) => (resolveStart = r)));

		await renderPage();
		const startBtn = screen.getByRole('button', { name: 'Start' }) as HTMLButtonElement;
		await fireEvent.click(startBtn);

		expect(startLab).toHaveBeenCalledOnce();
		// While the start is in flight, every lifecycle control is disabled.
		const killBtn = screen.getByRole('button', { name: 'Kill' }) as HTMLButtonElement;
		await waitFor(() => expect(killBtn.disabled).toBe(true));
		expect((screen.getByRole('button', { name: 'Starting…' }) as HTMLButtonElement).disabled).toBe(
			true
		);

		resolveStart({
			success: true,
			message: '',
			error: null,
			outcome: 'degraded_usable',
			diagnostics: [
				{ step: 'wait_for_services', impact: 'telemetry', severity: 'warning', message: 'slow' }
			]
		});

		await waitFor(() => expect(screen.getByText(/degraded_usable/i)).toBeTruthy());
		await waitFor(() => expect(refreshLabStatus).toHaveBeenCalled());
	});

	it('confirms an emergency kill through the dialog (processes only by default)', async () => {
		killLab.mockResolvedValue({
			success: true,
			mcp_processes_killed: 3,
			containers_stopped: false,
			session_cleared: true,
			errors: []
		});

		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Kill' }));

		const dialog = await screen.findByRole('dialog');
		expect(dialog.getAttribute('aria-labelledby')).toBeTruthy();

		await fireEvent.click(screen.getByRole('button', { name: /kill processes/i }));

		expect(killLab).toHaveBeenCalledWith(false);
		await waitFor(() => expect(screen.getByText(/Kill complete/i)).toBeTruthy());
		expect(screen.getByText(/3 MCP process\(es\) terminated/)).toBeTruthy();
		await waitFor(() => expect(refreshLabStatus).toHaveBeenCalled());
	});

	it('widens the kill blast radius when containers are toggled on', async () => {
		killLab.mockResolvedValue({
			success: true,
			mcp_processes_killed: 1,
			containers_stopped: true,
			session_cleared: true,
			errors: []
		});

		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Kill' }));
		await screen.findByRole('dialog');
		await fireEvent.click(
			screen.getByRole('checkbox', { name: /also force-stop all lab containers/i })
		);
		await fireEvent.click(screen.getByRole('button', { name: /kill \+ stop containers/i }));

		expect(killLab).toHaveBeenCalledWith(true);
		await waitFor(() => expect(screen.getByText(/containers stopped/i)).toBeTruthy());
	});

	it('cancelling the kill dialog runs no action', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Kill' }));
		await screen.findByRole('dialog');
		await fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
		await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
		expect(killLab).not.toHaveBeenCalled();
	});

	it('renders scenario cards from the catalog summary', async () => {
		await renderPage({
			scenarios: [
				{ id: 's1', name: 'Scenario One', description: 'first' },
				{ id: 's2', name: 'Scenario Two', description: 'second' }
			],
			scenariosError: false
		});
		expect(screen.getByText('Scenario One')).toBeTruthy();
		expect(screen.getByText('Scenario Two')).toBeTruthy();
		expect(screen.getByRole('link', { name: /Scenario One/ }).getAttribute('href')).toBe(
			'/scenarios/s1'
		);
	});

	it('shows an empty state when the catalog is empty', async () => {
		await renderPage({ scenarios: [], scenariosError: false });
		expect(screen.getByText(/No scenarios found/i)).toBeTruthy();
	});

	it('shows a catalog-unavailable state on load error', async () => {
		await renderPage({ scenarios: [], scenariosError: true });
		expect(screen.getByText(/catalog is currently unavailable/i)).toBeTruthy();
	});
});
