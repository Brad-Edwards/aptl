/** TypeScript mirror of `aptl.console.models`. Keep in sync. */

export type Role = 'red' | 'blue' | 'purple' | 'neutral';

export interface McpServerSpec {
	name: string;
	role: Role;
	command: string;
	args: string[];
	description: string;
	available: boolean;
	unavailable_reason: string;
}

export interface Scratchpad {
	id: string;
	name: string;
	content: string;
	created_at: number;
	updated_at: number;
}

export interface ToolCall {
	id: string;
	name: string;
	input: Record<string, unknown>;
	output: string;
	is_error: boolean;
}

export type MessageRole = 'user' | 'assistant' | 'system' | 'tool';

export interface ChatMessage {
	id: string;
	role: MessageRole;
	content: string;
	tool_calls: ToolCall[];
	created_at: number;
}

export interface Session {
	id: string;
	title: string;
	role: Role;
	mcp_servers: string[];
	scratchpads: string[];
	messages: ChatMessage[];
	created_at: number;
	updated_at: number;
}

export interface ProviderStatus {
	provider: string;
	model: string;
	live: boolean;
	detail: string;
}

export interface ConsoleState {
	sessions: Session[];
	scratchpads: Scratchpad[];
	servers: McpServerSpec[];
	provider: ProviderStatus;
}

/** Streamed turn events (mirrors the dicts yielded by the runtime). */
export type StreamEvent =
	| { type: 'user_message'; message: ChatMessage }
	| { type: 'assistant_message'; message: ChatMessage }
	| { type: 'token'; text: string }
	| { type: 'tool_call'; id: string; name: string; input: Record<string, unknown> }
	| { type: 'tool_result'; id: string; name: string; output: string; is_error: boolean }
	| { type: 'note'; message: string }
	| { type: 'error'; message: string }
	| { type: 'done'; text: string; tool_calls: ToolCall[] }
	| { type: 'end' };

export const ROLE_LABELS: Record<Role, string> = {
	red: 'Red',
	blue: 'Blue',
	purple: 'Purple',
	neutral: 'Neutral'
};
