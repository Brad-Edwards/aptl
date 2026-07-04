import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import { writable } from 'svelte/store';
import { vi } from 'vitest';
import type { LabStatus, ScenarioDetail } from '../../src/lib/types';

const labStatus = writable<LabStatus>({ running: false, containers: [], error: null });
vi.mock('$lib/stores/lab', () => ({ labStatus }));

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
	return render(Page, { props: { data } });
}

describe('Scenario workbench route', () => {
	beforeEach(() => {
		labStatus.set({ running: false, containers: [], error: null });
	});

	it('renders every workbench block family from the backend projection', async () => {
		await renderWorkbench({ scenario: detail() });

		// narrative markdown, section divider, objective, step, siem block.
		expect(screen.getByText('Heading')).toBeTruthy();
		expect(screen.getByText('Objectives')).toBeTruthy();
		expect(screen.getByText('Objective One')).toBeTruthy();
		expect(screen.getByText('step-one')).toBeTruthy();
		expect(screen.getByText('wazuh')).toBeTruthy();
	});

	it('keeps the SIEM query block execution disabled (owned by #421)', async () => {
		await renderWorkbench({ scenario: detail() });
		const runBtn = screen.getByRole('button', { name: 'Run Query' }) as HTMLButtonElement;
		expect(runBtn.disabled).toBe(true);
	});

	it('keeps the terminal block lazy — no PTY until an explicit action', async () => {
		await renderWorkbench({ scenario: detail() });
		// The lazy affordance is present; the maximize link (only shown once the
		// embedded terminal mounts) is not.
		expect(screen.getByRole('button', { name: /Open terminal: host-a/ })).toBeTruthy();
		expect(screen.queryByText('Maximize')).toBeNull();
	});

	it('surfaces an invalid scenario projection state in the status bar', async () => {
		await renderWorkbench({
			scenario: detail({ validation: { valid: false, detail: 'Scenario unavailable' } })
		});
		expect(screen.getByText('Scenario unavailable')).toBeTruthy();
	});
});
