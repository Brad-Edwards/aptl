import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import ScenarioCard from '../../src/lib/components/ScenarioCard.svelte';
import type { ScenarioSummary } from '../../src/lib/types';

const SCENARIO: ScenarioSummary = {
	id: 'techvault-operational',
	name: 'TechVault Operational',
	description: 'Default public APTL startup scenario backed by ACES SDL.'
};

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

	it('renders without a description', () => {
		render(ScenarioCard, {
			props: { scenario: { id: 'x', name: 'No Desc', description: '' } }
		});
		expect(screen.getByText('No Desc')).toBeTruthy();
	});
});
