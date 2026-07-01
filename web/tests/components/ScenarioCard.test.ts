import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import ScenarioCard from '../../src/lib/components/ScenarioCard.svelte';
import type { ScenarioSummary } from '../../src/lib/types';

const SCENARIO: ScenarioSummary = {
	id: 'techvault-operational',
	name: 'TechVault Operational',
	description: 'Default public APTL startup scenario backed by ACES SDL.',
	mode: 'purple',
	difficulty: 'advanced',
	estimated_minutes: 60,
	tags: ['soc', 'full-stack'],
	required_containers: ['wazuh-manager', 'misp'],
	validation: { valid: true, detail: null }
};

function summary(overrides: Partial<ScenarioSummary> = {}): ScenarioSummary {
	return { ...SCENARIO, ...overrides };
}

describe('ScenarioCard', () => {
	it('renders the name and description', () => {
		render(ScenarioCard, { props: { scenario: SCENARIO } });
		expect(screen.getByText('TechVault Operational')).toBeTruthy();
		expect(screen.getByText(/Default public APTL startup scenario/)).toBeTruthy();
	});

	it('links to the scenario workbench route', () => {
		render(ScenarioCard, { props: { scenario: SCENARIO } });
		const link = screen.getByRole('link');
		expect(link.getAttribute('href')).toBe('/scenarios/techvault-operational');
	});

	it('shows mode, difficulty, duration, container count, and tags', () => {
		render(ScenarioCard, { props: { scenario: SCENARIO } });
		expect(screen.getByText('purple')).toBeTruthy();
		expect(screen.getByText('advanced')).toBeTruthy();
		expect(screen.getByText('~60 min')).toBeTruthy();
		expect(screen.getByText('2 containers')).toBeTruthy();
		expect(screen.getByText('soc')).toBeTruthy();
	});

	it('marks an invalid scenario as unavailable', () => {
		render(ScenarioCard, {
			props: {
				scenario: summary({ validation: { valid: false, detail: 'nope' } })
			}
		});
		expect(screen.getByText('unavailable')).toBeTruthy();
	});

	it('renders with only the catalog-owned facts', () => {
		render(ScenarioCard, {
			props: {
				scenario: summary({
					name: 'Minimal',
					description: '',
					mode: null,
					difficulty: null,
					estimated_minutes: null,
					tags: [],
					required_containers: []
				})
			}
		});
		expect(screen.getByText('Minimal')).toBeTruthy();
	});
});
