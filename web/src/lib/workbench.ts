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
 * Build the title narrative block (name, description, and metadata line).
 */
function buildTitleNarrative(scenario: ScenarioDefinition): NarrativeBlock {
	const meta = scenario.metadata;
	const metaParts: string[] = [];
	if (meta.difficulty) metaParts.push(`**Difficulty:** ${meta.difficulty}`);
	if (meta.estimated_minutes) metaParts.push(`**Time:** ~${meta.estimated_minutes} min`);
	if (scenario.mode) metaParts.push(`**Mode:** ${scenario.mode}`);
	if (meta.tags.length > 0) metaParts.push(`**Tags:** ${meta.tags.join(', ')}`);
	if (meta.mitre_attack.tactics.length > 0)
		metaParts.push(`**MITRE Tactics:** ${meta.mitre_attack.tactics.join(', ')}`);
	if (meta.mitre_attack.techniques.length > 0)
		metaParts.push(`**MITRE Techniques:** ${meta.mitre_attack.techniques.join(', ')}`);

	return {
		type: 'narrative',
		key: 'narrative-title',
		content: `# ${meta.name}\n\n${meta.description}\n\n${metaParts.join(' | ')}`
	};
}

/**
 * Build the attack-step section: a divider followed by one block per step.
 * Returns an empty array when the scenario has no steps.
 */
function buildStepBlocks(steps: ScenarioDefinition['steps']): WorkbenchBlock[] {
	if (steps.length === 0) return [];
	const blocks: WorkbenchBlock[] = [
		{ type: 'section-divider', key: 'divider-steps', title: 'Attack Steps' }
	];
	for (let i = 0; i < steps.length; i++) {
		blocks.push({
			type: 'attack-step',
			key: `step-${steps[i].step_number}`,
			step: steps[i],
			stepIndex: i
		});
	}
	return blocks;
}

/**
 * Build the objectives section: a divider when any objective exists, then the
 * red objectives followed by the blue objectives.
 */
function buildObjectiveBlocks(objectives: ScenarioDefinition['objectives']): WorkbenchBlock[] {
	const blocks: WorkbenchBlock[] = [];
	if (objectives.red.length > 0 || objectives.blue.length > 0) {
		blocks.push({ type: 'section-divider', key: 'divider-objectives', title: 'Objectives' });
	}
	for (const obj of objectives.red) {
		blocks.push({ type: 'objective', key: `obj-red-${obj.id}`, objective: obj, team: 'red' });
	}
	for (const obj of objectives.blue) {
		blocks.push({ type: 'objective', key: `obj-blue-${obj.id}`, objective: obj, team: 'blue' });
	}
	return blocks;
}

/**
 * Build the scoring narrative block, or null when the scenario has no scoring.
 */
function buildScoringNarrative(scoring: ScenarioDefinition['scoring']): NarrativeBlock | null {
	if (scoring.max_score <= 0) return null;
	let scoringText = `## Scoring\n\n**Max score:** ${scoring.max_score}`;
	if (scoring.passing_score > 0) scoringText += ` | **Passing:** ${scoring.passing_score}`;
	if (scoring.time_bonus.enabled) {
		scoringText += `\n\n**Time bonus:** up to ${scoring.time_bonus.max_bonus} points (decays after ${scoring.time_bonus.decay_after_minutes} min)`;
	}
	return { type: 'narrative', key: 'narrative-scoring', content: scoringText };
}

/**
 * Build an ordered array of workbench blocks from a scenario definition.
 * Pure function -- no side effects, fully testable without DOM.
 */
export function buildBlockSequence(scenario: ScenarioDefinition): WorkbenchBlock[] {
	const containers = scenario.containers.required;
	const containerStatus: WorkbenchBlock[] =
		containers.length > 0
			? [{ type: 'container-status', key: 'container-status', containers }]
			: [];
	const attackChain: WorkbenchBlock[] = scenario.attack_chain
		? [
				{
					type: 'narrative',
					key: 'narrative-attack-chain',
					content: `## Attack Chain\n\n${scenario.attack_chain}`
				}
			]
		: [];
	const scoring = buildScoringNarrative(scenario.scoring);

	return [
		// 1. Title narrative
		buildTitleNarrative(scenario),
		// 2. Container status
		...containerStatus,
		// 3. Attack chain summary
		...attackChain,
		// 4. Steps
		...buildStepBlocks(scenario.steps),
		// 5-7. Objectives
		...buildObjectiveBlocks(scenario.objectives),
		// 8. Scoring summary
		...(scoring ? [scoring] : [])
	];
}
