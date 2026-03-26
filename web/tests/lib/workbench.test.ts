import { describe, it, expect } from 'vitest';
import { buildBlockSequence, type WorkbenchBlock } from '../../src/lib/workbench';
import type { ScenarioDefinition } from '../../src/lib/types';

function makeScenario(overrides: Partial<ScenarioDefinition> = {}): ScenarioDefinition {
	return {
		metadata: {
			id: 'test-scenario',
			name: 'Test Scenario',
			description: 'A test scenario.',
			version: '1.0.0',
			author: 'tester',
			difficulty: 'intermediate',
			estimated_minutes: 30,
			tags: ['recon'],
			mitre_attack: { tactics: ['TA0043'], techniques: ['T1595'] }
		},
		mode: 'purple',
		containers: { required: ['victim', 'kali'] },
		preconditions: [],
		objectives: { red: [], blue: [] },
		scoring: {
			time_bonus: { enabled: false, max_bonus: 0, decay_after_minutes: 10 },
			passing_score: 0,
			max_score: 0
		},
		attack_chain: '',
		steps: [],
		...overrides
	};
}

function blockTypes(blocks: WorkbenchBlock[]): string[] {
	return blocks.map((b) => b.type);
}

describe('buildBlockSequence', () => {
	it('always starts with narrative (title) and container-status', () => {
		const blocks = buildBlockSequence(makeScenario());
		expect(blocks[0].type).toBe('narrative');
		expect(blocks[1].type).toBe('container-status');
		if (blocks[1].type === 'container-status') {
			expect(blocks[1].containers).toEqual(['victim', 'kali']);
		}
	});

	it('title narrative contains scenario name and metadata', () => {
		const blocks = buildBlockSequence(makeScenario());
		if (blocks[0].type === 'narrative') {
			expect(blocks[0].content).toContain('# Test Scenario');
			expect(blocks[0].content).toContain('intermediate');
			expect(blocks[0].content).toContain('30 min');
			expect(blocks[0].content).toContain('T1595');
		}
	});

	it('includes attack chain narrative when present', () => {
		const blocks = buildBlockSequence(
			makeScenario({ attack_chain: 'Recon -> Exploit -> Persist' })
		);
		const chainBlock = blocks.find(
			(b) => b.type === 'narrative' && b.content.includes('Attack Chain')
		);
		expect(chainBlock).toBeDefined();
	});

	it('does not include attack chain narrative when empty', () => {
		const blocks = buildBlockSequence(makeScenario({ attack_chain: '' }));
		const chainBlock = blocks.find(
			(b) => b.type === 'narrative' && b.content.includes('Attack Chain')
		);
		expect(chainBlock).toBeUndefined();
	});

	it('renders steps-only scenario', () => {
		const blocks = buildBlockSequence(
			makeScenario({
				steps: [
					{
						step_number: 1,
						technique_id: 'T1595.002',
						technique_name: 'Active Scanning',
						tactic: 'Reconnaissance',
						description: 'Scan the target',
						target: 'victim',
						vulnerability: '',
						commands: ['nmap -sV victim'],
						prerequisites: [],
						expected_detections: [],
						investigation_hints: [],
						remediation: []
					}
				]
			})
		);
		const types = blockTypes(blocks);
		expect(types).toContain('section-divider');
		expect(types).toContain('attack-step');
		expect(types).not.toContain('objective');
	});

	it('renders objectives-only scenario', () => {
		const blocks = buildBlockSequence(
			makeScenario({
				objectives: {
					red: [],
					blue: [
						{
							id: 'detect-scan',
							description: 'Detect the scan',
							type: 'wazuh_alert',
							points: 100,
							hints: []
						}
					]
				}
			})
		);
		const types = blockTypes(blocks);
		expect(types).toContain('objective');
		expect(types).not.toContain('attack-step');
	});

	it('renders purple (both steps and objectives) scenario', () => {
		const blocks = buildBlockSequence(
			makeScenario({
				steps: [
					{
						step_number: 1,
						technique_id: 'T1595',
						technique_name: 'Scan',
						tactic: 'Recon',
						description: 'Scan',
						target: 'victim',
						vulnerability: '',
						commands: [],
						prerequisites: [],
						expected_detections: [],
						investigation_hints: [],
						remediation: []
					}
				],
				objectives: {
					red: [
						{
							id: 'obj-red',
							description: 'Red objective',
							type: 'manual',
							points: 50,
							hints: []
						}
					],
					blue: [
						{
							id: 'obj-blue',
							description: 'Blue objective',
							type: 'manual',
							points: 50,
							hints: []
						}
					]
				}
			})
		);
		const types = blockTypes(blocks);
		expect(types).toContain('attack-step');
		expect(types).toContain('objective');
		// Objectives divider appears after steps
		const stepIdx = types.indexOf('attack-step');
		const objDivider = types.indexOf('section-divider', stepIdx + 1);
		expect(objDivider).toBeGreaterThan(stepIdx);
	});

	it('separates red and blue objectives with correct team', () => {
		const blocks = buildBlockSequence(
			makeScenario({
				objectives: {
					red: [
						{
							id: 'r1',
							description: 'Red',
							type: 'manual',
							points: 10,
							hints: []
						}
					],
					blue: [
						{
							id: 'b1',
							description: 'Blue',
							type: 'manual',
							points: 10,
							hints: []
						}
					]
				}
			})
		);
		const objBlocks = blocks.filter((b) => b.type === 'objective');
		expect(objBlocks).toHaveLength(2);
		if (objBlocks[0].type === 'objective' && objBlocks[1].type === 'objective') {
			expect(objBlocks[0].team).toBe('red');
			expect(objBlocks[1].team).toBe('blue');
		}
	});

	it('includes scoring narrative when max_score > 0', () => {
		const blocks = buildBlockSequence(
			makeScenario({
				scoring: {
					time_bonus: { enabled: true, max_bonus: 50, decay_after_minutes: 15 },
					passing_score: 60,
					max_score: 200
				}
			})
		);
		const scoringBlock = blocks.find(
			(b) => b.type === 'narrative' && b.content.includes('Scoring')
		);
		expect(scoringBlock).toBeDefined();
		if (scoringBlock?.type === 'narrative') {
			expect(scoringBlock.content).toContain('200');
			expect(scoringBlock.content).toContain('60');
			expect(scoringBlock.content).toContain('50 points');
			expect(scoringBlock.content).toContain('15 min');
		}
	});

	it('omits scoring narrative when max_score is 0', () => {
		const blocks = buildBlockSequence(makeScenario());
		const scoringBlock = blocks.find(
			(b) => b.type === 'narrative' && b.content.includes('Scoring')
		);
		expect(scoringBlock).toBeUndefined();
	});

	it('preserves step order by array index', () => {
		const blocks = buildBlockSequence(
			makeScenario({
				steps: [
					{
						step_number: 1,
						technique_id: 'T1',
						technique_name: 'First',
						tactic: 'T',
						description: 'First',
						target: 'victim',
						vulnerability: '',
						commands: [],
						prerequisites: [],
						expected_detections: [],
						investigation_hints: [],
						remediation: []
					},
					{
						step_number: 2,
						technique_id: 'T2',
						technique_name: 'Second',
						tactic: 'T',
						description: 'Second',
						target: 'victim',
						vulnerability: '',
						commands: [],
						prerequisites: [],
						expected_detections: [],
						investigation_hints: [],
						remediation: []
					}
				]
			})
		);
		const stepBlocks = blocks.filter((b) => b.type === 'attack-step');
		expect(stepBlocks).toHaveLength(2);
		if (stepBlocks[0].type === 'attack-step' && stepBlocks[1].type === 'attack-step') {
			expect(stepBlocks[0].stepIndex).toBe(0);
			expect(stepBlocks[1].stepIndex).toBe(1);
		}
	});
});
