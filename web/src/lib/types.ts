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

/** APTL configuration. */
export interface AppConfig {
	lab_name: string;
	network_subnet: string;
	containers: Record<string, boolean>;
	run_storage_backend: string;
}
