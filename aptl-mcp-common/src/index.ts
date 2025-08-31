// Export the working SSH implementation exactly as-is
export { 
  SSHConnectionManager, 
  PersistentSession, 
  SSHError, 
  CommandResult, 
  SessionType, 
  SessionMode, 
  SessionMetadata, 
  CommandRequest 
} from './ssh.js';
export { expandTilde } from './utils.js';

// Export MCP server creation and types
export { createMCPServer } from './server.js';
export type { LabConfig } from './config.js';
export type { ToolContext } from './tools/handlers.js';