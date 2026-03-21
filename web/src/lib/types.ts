/** Container status from the API. */
export interface ContainerInfo {
	name: string;
	state: string;
	status: string;
	health: string;
	image: string;
	ports: string[];
}

/** Lab status response. */
export interface LabStatus {
	running: boolean;
	containers: ContainerInfo[];
	error: string | null;
}

/** Lab action response (start/stop). */
export interface LabActionResponse {
	success: boolean;
	message: string;
	error: string | null;
}

/** Scenario summary for listing. */
export interface ScenarioSummary {
	id: string;
	name: string;
	description: string;
	difficulty: string;
	mode: string;
	estimated_minutes: number;
	tags: string[];
	containers_required: string[];
}

// --- Full scenario definition types (mirrors Python core/scenarios.py) ---

export type Difficulty = 'beginner' | 'intermediate' | 'advanced' | 'expert';
export type ScenarioMode = 'red' | 'blue' | 'purple';
export type ObjectiveType = 'manual' | 'wazuh_alert' | 'command_output' | 'file_exists';
export type PreconditionType = 'exec' | 'file';

export interface MitreReference {
	tactics: string[];
	techniques: string[];
}

export interface ScenarioMetadata {
	id: string;
	name: string;
	description: string;
	version: string;
	author: string;
	difficulty: Difficulty;
	estimated_minutes: number;
	tags: string[];
	mitre_attack: MitreReference;
}

export interface ContainerRequirements {
	required: string[];
}

export interface Precondition {
	type: PreconditionType;
	container: string;
	description: string;
	command?: string;
	path?: string;
	content?: string;
}

export interface Hint {
	level: number;
	text: string;
	point_penalty: number;
}

export interface WazuhAlertValidation {
	query: Record<string, unknown>;
	min_matches: number;
	time_window_seconds: number;
}

export interface CommandOutputValidation {
	container: string;
	command: string;
	contains: string[];
	regex?: string;
}

export interface FileExistsValidation {
	container: string;
	path: string;
	contains?: string;
}

export interface Objective {
	id: string;
	description: string;
	type: ObjectiveType;
	points: number;
	hints: Hint[];
	wazuh_alert?: WazuhAlertValidation;
	command_output?: CommandOutputValidation;
	file_exists?: FileExistsValidation;
}

export interface ObjectiveSet {
	red: Objective[];
	blue: Objective[];
}

export interface TimeBonusConfig {
	enabled: boolean;
	max_bonus: number;
	decay_after_minutes: number;
}

export interface ScoringConfig {
	time_bonus: TimeBonusConfig;
	passing_score: number;
	max_score: number;
}

export interface ExpectedDetection {
	product_name: string;
	analytic_uid?: string;
	analytic_name?: string;
	severity_id: number;
	description: string;
	max_detection_time_seconds: number;
}

export interface AttackStep {
	step_number: number;
	technique_id: string;
	technique_name: string;
	tactic: string;
	description: string;
	target: string;
	vulnerability: string;
	commands: string[];
	prerequisites: string[];
	expected_detections: ExpectedDetection[];
	investigation_hints: string[];
	remediation: string[];
}

export interface ScenarioDefinition {
	metadata: ScenarioMetadata;
	mode: ScenarioMode;
	containers: ContainerRequirements;
	preconditions: Precondition[];
	objectives: ObjectiveSet;
	scoring: ScoringConfig;
	attack_chain: string;
	steps: AttackStep[];
	defenses?: Record<string, unknown>;
}

/** APTL configuration. */
export interface AppConfig {
	lab_name: string;
	network_subnet: string;
	containers: Record<string, boolean>;
	run_storage_backend: string;
}
