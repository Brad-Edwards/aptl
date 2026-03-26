import type { AttackStep, Objective, ScenarioDefinition } from './types';

// --- Block discriminated union ---

export interface NarrativeBlock {
	type: 'narrative';
	key: string;
	content: string;
}

export interface ContainerStatusBlock {
	type: 'container-status';
	key: string;
	containers: string[];
}

export interface AttackStepBlock {
	type: 'attack-step';
	key: string;
	step: AttackStep;
	stepIndex: number;
}

export interface SectionDividerBlock {
	type: 'section-divider';
	key: string;
	title: string;
}

export interface ObjectiveBlock {
	type: 'objective';
	key: string;
	objective: Objective;
	team: 'red' | 'blue';
}

export type WorkbenchBlock =
	| NarrativeBlock
	| ContainerStatusBlock
	| AttackStepBlock
	| SectionDividerBlock
	| ObjectiveBlock;

/**
 * Build an ordered array of workbench blocks from a scenario definition.
 * Pure function -- no side effects, fully testable without DOM.
 */
export function buildBlockSequence(scenario: ScenarioDefinition): WorkbenchBlock[] {
	const blocks: WorkbenchBlock[] = [];
	const meta = scenario.metadata;

	// 1. Title narrative
	const metaParts: string[] = [];
	if (meta.difficulty) metaParts.push(`**Difficulty:** ${meta.difficulty}`);
	if (meta.estimated_minutes) metaParts.push(`**Time:** ~${meta.estimated_minutes} min`);
	if (scenario.mode) metaParts.push(`**Mode:** ${scenario.mode}`);
	if (meta.tags.length > 0) metaParts.push(`**Tags:** ${meta.tags.join(', ')}`);
	if (meta.mitre_attack.tactics.length > 0)
		metaParts.push(`**MITRE Tactics:** ${meta.mitre_attack.tactics.join(', ')}`);
	if (meta.mitre_attack.techniques.length > 0)
		metaParts.push(`**MITRE Techniques:** ${meta.mitre_attack.techniques.join(', ')}`);

	blocks.push({
		type: 'narrative',
		key: 'narrative-title',
		content: `# ${meta.name}\n\n${meta.description}\n\n${metaParts.join(' | ')}`
	});

	// 2. Container status
	const containers = scenario.containers.required;
	if (containers.length > 0) {
		blocks.push({ type: 'container-status', key: 'container-status', containers });
	}

	// 3. Attack chain summary
	if (scenario.attack_chain) {
		blocks.push({
			type: 'narrative',
			key: 'narrative-attack-chain',
			content: `## Attack Chain\n\n${scenario.attack_chain}`
		});
	}

	// 4. Steps
	if (scenario.steps.length > 0) {
		blocks.push({ type: 'section-divider', key: 'divider-steps', title: 'Attack Steps' });
		for (let i = 0; i < scenario.steps.length; i++) {
			blocks.push({
				type: 'attack-step',
				key: `step-${scenario.steps[i].step_number}`,
				step: scenario.steps[i],
				stepIndex: i
			});
		}
	}

	// 5-7. Objectives
	const hasRed = scenario.objectives.red.length > 0;
	const hasBlue = scenario.objectives.blue.length > 0;
	if (hasRed || hasBlue) {
		blocks.push({ type: 'section-divider', key: 'divider-objectives', title: 'Objectives' });
	}
	for (const obj of scenario.objectives.red) {
		blocks.push({ type: 'objective', key: `obj-red-${obj.id}`, objective: obj, team: 'red' });
	}
	for (const obj of scenario.objectives.blue) {
		blocks.push({ type: 'objective', key: `obj-blue-${obj.id}`, objective: obj, team: 'blue' });
	}

	// 8. Scoring summary
	if (scenario.scoring.max_score > 0) {
		const s = scenario.scoring;
		let scoringText = `## Scoring\n\n**Max score:** ${s.max_score}`;
		if (s.passing_score > 0) scoringText += ` | **Passing:** ${s.passing_score}`;
		if (s.time_bonus.enabled) {
			scoringText += `\n\n**Time bonus:** up to ${s.time_bonus.max_bonus} points (decays after ${s.time_bonus.decay_after_minutes} min)`;
		}
		blocks.push({ type: 'narrative', key: 'narrative-scoring', content: scoringText });
	}

	return blocks;
}
