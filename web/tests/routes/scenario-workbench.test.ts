import { describe, it, expect, beforeEach } from 'vitest';
import { render, within } from '@testing-library/svelte';
import { writable } from 'svelte/store';
import { vi } from 'vitest';
import type { LabStatus, ScenarioDetail } from '../../src/lib/types';

const labStatus = writable<LabStatus>({ running: false, containers: [], error: null });
vi.mock('$lib/stores/lab', () => ({ labStatus }));

// Stub the DOM-canvas terminal deps, exactly as tests/components/workbench/blocks.test.ts
// and tests/routes/terminal-page.test.ts already do. This file renders the whole
// workbench page, whose fixture includes a `terminal` block, so without these stubs
// it is the only suite that pulls xterm's lazy dynamic import into a jsdom render.
// That import resolving after the test had finished is what intermittently left DOM
// attached and produced "found multiple elements" under CPU contention (issue #852).
vi.mock('@xterm/xterm', () => ({
	Terminal: vi.fn(function () {
		return {
			loadAddon: vi.fn(),
			open: vi.fn(),
			onData: vi.fn(),
			onResize: vi.fn(),
			write: vi.fn(),
			dispose: vi.fn(),
			cols: 80,
			rows: 24
		};
	})
}));
vi.mock('@xterm/addon-fit', () => ({
	FitAddon: vi.fn(function () {
		return { fit: vi.fn(), dispose: vi.fn() };
	})
}));
vi.mock('@xterm/addon-web-links', () => ({
	WebLinksAddon: vi.fn(function () {
		return { dispose: vi.fn() };
	})
}));
vi.mock('@xterm/xterm/css/xterm.css', () => ({}));

function detail(overrides: Partial<ScenarioDetail> = {}): ScenarioDetail {
	return {
		id: 'demo',
		name: 'Demo Scenario',
		description: 'A demo.',
		mode: 'purple',
		difficulty: 'advanced',
		estimated_minutes: 45,
		tags: ['demo'],
		required_containers: ['host-a'],
		validation: { valid: true, detail: null },
		blocks: [
			{ type: 'narrative', key: 'n', content: '# Heading\n\nBody text.' },
			{ type: 'container-status', key: 'cs', containers: ['host-a'] },
			{ type: 'section-divider', key: 'd', title: 'Objectives' },
			{
				type: 'objective',
				key: 'o',
				name: 'Objective One',
				description: 'achieve it',
				success: 'all_of: metrics m1'
			},
			{
				type: 'step',
				key: 's',
				index: 0,
				name: 'step-one',
				description: 'run the probe',
				step_type: 'action'
			},
			{
				type: 'siem-query',
				key: 'q',
				product_name: 'wazuh',
				description: 'recent alerts',
				query: { match: 'x' }
			},
			{ type: 'terminal', key: 't', container: 'host-a', label: 'host-a' }
		],
		...overrides
	};
}

async function renderWorkbench(data: { scenario: ScenarioDetail }) {
	const Page = (await import('../../src/routes/scenarios/[id]/+page.svelte')).default;
	const { container } = render(Page, { props: { data } });
	// Scope queries to THIS render's container rather than the global `screen`
	// (which searches all of document.body). Under CPU contention these tests
	// intermittently matched a previous test's still-attached DOM and failed with
	// "found multiple elements" (issue #852). A scoped query asserts against the
	// component actually under test, so the assertion is both correct and immune
	// to a leaked sibling container.
	return within(container);
}

describe('Scenario workbench route', () => {
	beforeEach(() => {
		labStatus.set({ running: false, containers: [], error: null });
	});

	it('renders every workbench block family from the backend projection', async () => {
		const view = await renderWorkbench({ scenario: detail() });

		// narrative markdown, section divider, objective, step, siem block.
		expect(view.getByText('Heading')).toBeTruthy();
		expect(view.getByText('Objectives')).toBeTruthy();
		expect(view.getByText('Objective One')).toBeTruthy();
		expect(view.getByText('step-one')).toBeTruthy();
		expect(view.getByText('wazuh')).toBeTruthy();
	});

	it('keeps the SIEM query block execution disabled (owned by #421)', async () => {
		const view = await renderWorkbench({ scenario: detail() });
		const runBtn = view.getByRole('button', { name: 'Run Query' }) as HTMLButtonElement;
		expect(runBtn.disabled).toBe(true);
	});

	it('keeps the terminal block lazy — no PTY until an explicit action', async () => {
		const view = await renderWorkbench({ scenario: detail() });
		// The lazy affordance is present; the maximize link (only shown once the
		// embedded terminal mounts) is not.
		expect(view.getByRole('button', { name: /Open terminal: host-a/ })).toBeTruthy();
		expect(view.queryByText('Maximize')).toBeNull();
	});

	it('surfaces an invalid scenario projection state in the status bar', async () => {
		const view = await renderWorkbench({
			scenario: detail({ validation: { valid: false, detail: 'Scenario unavailable' } })
		});
		expect(view.getByText('Scenario unavailable')).toBeTruthy();
	});
});
