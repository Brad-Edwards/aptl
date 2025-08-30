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