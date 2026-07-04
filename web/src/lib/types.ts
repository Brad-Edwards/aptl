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

/** Stable wire strings from `aptl.core.lab_types.StartupOutcome` (ADR-030). */
export type StartupOutcome =
	| 'ready'
	| 'degraded_usable'
	| 'degraded_unusable'
	| 'failed';

/** Stable wire strings from `aptl.core.lab_types.DiagnosticImpact` (ADR-030). */
export type DiagnosticImpact = 'cosmetic' | 'telemetry' | 'capability' | 'readiness';

/** Stable wire strings from `aptl.core.lab_types.DiagnosticSeverity` (ADR-030). */
export type DiagnosticSeverity = 'info' | 'warning' | 'error';

/** A structured note emitted by one startup step (ADR-030). */
export interface StartupDiagnostic {
	step: string;
	impact: DiagnosticImpact;
	severity: DiagnosticSeverity;
	message: string;
	component?: string;
	operator_action?: string;
}

/** Lab action response (start/stop).
 *
 *  `outcome` and `diagnostics` carry ADR-030's structured partial-readiness
 *  classification. Both are optional: older API builds (or `/lab/stop`,
 *  which has no degraded state today) may omit them.
 */
export interface LabActionResponse {
	success: boolean;
	message: string;
	error: string | null;
	outcome?: StartupOutcome | null;
	diagnostics?: StartupDiagnostic[];
}

/** Response for POST /api/lab/kill.
 *
 *  Mirrors `aptl.api.schemas.KillActionResponse`. Kept distinct from
 *  `LabActionResponse` (start/stop) on purpose — kill reports its own
 *  blast-radius outcome (processes killed, whether containers were also
 *  stopped) rather than an ADR-030 startup outcome.
 */
export interface KillActionResponse {
	success: boolean;
	mcp_processes_killed: number;
	containers_stopped: boolean;
	session_cleared: boolean;
	errors: string[];
}

export type ScenarioMode = 'red' | 'blue' | 'purple';
export type ScenarioDifficulty = 'beginner' | 'intermediate' | 'advanced' | 'expert';

/** Whether a catalog entry resolved and its ACES SDL projected cleanly.
 *
 *  Mirrors `aptl.api.schemas.ScenarioValidationState`. Distinct from lab
 *  readiness, container health, objective completion, and scoring: `valid`
 *  means only that the catalog entry and its ACES projection loaded/validated.
 *  `detail` carries a redacted user-facing reason when `valid` is `false`.
 */
export interface ScenarioValidation {
	valid: boolean;
	detail: string | null;
}

/** Enriched scenario card summary for the Lab Home entry points (UI-008d).
 *
 *  Mirrors `aptl.api.schemas.ScenarioSummaryResponse`: catalog-owned id/name/
 *  description, the narrow catalog metadata extension (mode/difficulty/
 *  estimated_minutes/tags), plus required containers and validation projected
 *  from the ACES SDL. The internal catalog `path` locator is never exposed.
 */
export interface ScenarioSummary {
	id: string;
	name: string;
	description: string;
	mode: ScenarioMode | null;
	difficulty: ScenarioDifficulty | null;
	estimated_minutes: number | null;
	tags: string[];
	required_containers: string[];
	validation: ScenarioValidation;
}

// --- Scenario-detail workbench projection (UI-008d) ---
//
// Mirrors the backend-owned wire shapes in `aptl.api.schemas`. The ordered
// `WorkbenchBlock` discriminated union — NOT the removed legacy in-tree
// scenario model — is the contract; the route renders these blocks directly
// from the API. Blocks are display/action descriptors, not authorities.

export interface NarrativeBlock {
	type: 'narrative';
	key: string;
	content: string;
}

export interface SectionDividerBlock {
	type: 'section-divider';
	key: string;
	title: string;
}

export interface ContainerStatusBlock {
	type: 'container-status';
	key: string;
	containers: string[];
}

export interface ObjectiveBlock {
	type: 'objective';
	key: string;
	name: string;
	description: string;
	success: string;
}

export interface StepBlock {
	type: 'step';
	key: string;
	index: number;
	name: string;
	description: string;
	step_type: string;
}

export interface SiemQueryBlock {
	type: 'siem-query';
	key: string;
	product_name: string;
	description: string;
	query: Record<string, unknown>;
}

export interface TerminalBlock {
	type: 'terminal';
	key: string;
	container: string;
	label: string;
}

export type WorkbenchBlock =
	| NarrativeBlock
	| SectionDividerBlock
	| ContainerStatusBlock
	| ObjectiveBlock
	| StepBlock
	| SiemQueryBlock
	| TerminalBlock;

/** Full scenario-detail projection for `/scenarios/[id]`.
 *
 *  Mirrors `aptl.api.schemas.ScenarioDetailResponse`: header facts plus an
 *  ordered `WorkbenchBlock` union. Never carries the catalog `path` locator or
 *  raw parser output.
 */
export interface ScenarioDetail {
	id: string;
	name: string;
	description: string;
	mode: ScenarioMode | null;
	difficulty: ScenarioDifficulty | null;
	estimated_minutes: number | null;
	tags: string[];
	required_containers: string[];
	validation: ScenarioValidation;
	blocks: WorkbenchBlock[];
}

/** APTL configuration. */
export interface AppConfig {
	lab_name: string;
	network_subnet: string;
	containers: Record<string, boolean>;
	run_storage_backend: string;
}
