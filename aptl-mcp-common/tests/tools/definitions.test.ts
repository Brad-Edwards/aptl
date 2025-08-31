import { describe, it, expect } from 'vitest';
import { generateToolDefinitions } from '../../src/tools/definitions.js';
import type { LabConfig } from '../../src/config.js';

describe('Tool Definition Tests', () => {
  describe('generateToolDefinitions - Basic Functionality', () => {
    it('should generate tools with correct toolPrefix', () => {
      const serverConfig: LabConfig['server'] = {
        name: 'test-server',
        version: '1.0.0',
        description: 'Test server',
        toolPrefix: 'test_prefix',
        targetName: 'Test Target',
        configKey: 'test-container',
        envPrefix: 'TEST'
      };

      const tools = generateToolDefinitions(serverConfig);
      
      // Check all tools have correct prefix
      const expectedToolNames = [
        'test_prefix_info',
        'test_prefix_run_command',
        'test_prefix_interactive_session',
        'test_prefix_background_session', 
        'test_prefix_session_command',
        'test_prefix_list_sessions',
        'test_prefix_close_session',
        'test_prefix_get_session_output',
        'test_prefix_close_all_sessions'
      ];

      const actualToolNames = tools.map(tool => tool.name);
      expect(actualToolNames).toEqual(expectedToolNames);
    });

    it('should use targetName in tool descriptions', () => {
      const serverConfig: LabConfig['server'] = {
        name: 'minetest-server',
        version: '1.0.0',
        description: 'Minetest server',
        toolPrefix: 'mc_server',
        targetName: 'Minetest Server',
        configKey: 'minetest-server',
        envPrefix: 'MINETEST_SERVER'
      };

      const tools = generateToolDefinitions(serverConfig);
      
      const infoTool = tools.find(t => t.name === 'mc_server_info');
      const runCommandTool = tools.find(t => t.name === 'mc_server_run_command');

      expect(infoTool?.description).toBe('Get information about the Minetest Server instance in the lab');
      expect(runCommandTool?.description).toBe('Execute a command on the Minetest Server instance (creates temporary session)');
      expect(runCommandTool?.inputSchema.properties.command.description).toBe('Command to execute on Minetest Server');
    });

    it('should generate correct number of tools', () => {
      const serverConfig: LabConfig['server'] = {
        name: 'kali-server',
        version: '1.0.0',
        description: 'Kali server',
        toolPrefix: 'kali',
        targetName: 'Kali Linux',
        configKey: 'kali',
        envPrefix: 'KALI'
      };

      const tools = generateToolDefinitions(serverConfig);
      expect(tools).toHaveLength(9);
    });
  });

  describe('Tool Schema Validation', () => {
    const serverConfig: LabConfig['server'] = {
      name: 'test-server',
      version: '1.0.0',
      description: 'Test server',
      toolPrefix: 'test',
      targetName: 'Test Target',
      configKey: 'test-container',
      envPrefix: 'TEST'
    };

    it('should have correct input schema for info tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const infoTool = tools.find(t => t.name === 'test_info');

      expect(infoTool).toBeDefined();
      expect(infoTool?.inputSchema).toEqual({
        type: 'object',
        properties: {},
      });
    });

    it('should have correct input schema for run_command tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const runCommandTool = tools.find(t => t.name === 'test_run_command');

      expect(runCommandTool).toBeDefined();
      expect(runCommandTool?.inputSchema).toEqual({
        type: 'object',
        properties: {
          command: {
            type: 'string',
            description: 'Command to execute on Test Target',
          },
        },
        required: ['command'],
      });
    });

    it('should have correct input schema for interactive_session tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const sessionTool = tools.find(t => t.name === 'test_interactive_session');

      expect(sessionTool).toBeDefined();
      expect(sessionTool?.inputSchema).toEqual({
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Unique session identifier (optional, auto-generated if not provided)',
          },
          timeout_ms: {
            type: 'number',
            description: 'Session timeout in milliseconds before automatic closure (default: 600000 = 10 minutes)',
            default: 600000,
          },
        },
        required: [],
      });
    });

    it('should have correct input schema for background_session tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const bgSessionTool = tools.find(t => t.name === 'test_background_session');

      expect(bgSessionTool).toBeDefined();
      expect(bgSessionTool?.inputSchema).toEqual({
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Unique session identifier (optional, auto-generated if not provided)',
          },
          raw: {
            type: 'boolean',
            description: 'Use raw mode for interactive programs (msfconsole, scanmem, gdb) that need clean stdin/stdout',
            default: false,
          },
          timeout_ms: {
            type: 'number',
            description: 'Session timeout in milliseconds before automatic closure (default: 600000 = 10 minutes)',
            default: 600000,
          },
        },
        required: [],
      });
    });

    it('should have correct input schema for session_command tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const sessionCommandTool = tools.find(t => t.name === 'test_session_command');

      expect(sessionCommandTool).toBeDefined();
      expect(sessionCommandTool?.inputSchema).toEqual({
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Session identifier to execute command in',
          },
          command: {
            type: 'string',
            description: 'Command to execute',
          },
          timeout: {
            type: 'number',
            description: 'Command timeout in milliseconds (default: 30000)',
            default: 30000,
          },
          raw: {
            type: 'boolean',
            description: 'Execute in raw mode (no echo wrapping, for interactive programs). Defaults to session mode',
            default: false,
          },
        },
        required: ['session_id', 'command'],
      });
    });

    it('should have correct input schema for list_sessions tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const listSessionsTool = tools.find(t => t.name === 'test_list_sessions');

      expect(listSessionsTool).toBeDefined();
      expect(listSessionsTool?.inputSchema).toEqual({
        type: 'object',
        properties: {},
      });
    });

    it('should have correct input schema for close_session tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const closeSessionTool = tools.find(t => t.name === 'test_close_session');

      expect(closeSessionTool).toBeDefined();
      expect(closeSessionTool?.inputSchema).toEqual({
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Session identifier to close',
          },
        },
        required: ['session_id'],
      });
    });

    it('should have correct input schema for get_session_output tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const getOutputTool = tools.find(t => t.name === 'test_get_session_output');

      expect(getOutputTool).toBeDefined();
      expect(getOutputTool?.inputSchema).toEqual({
        type: 'object',
        properties: {
          session_id: {
            type: 'string',
            description: 'Session identifier to get output from',
          },
          lines: {
            type: 'number',
            description: 'Number of recent lines to retrieve (optional, default: all)',
          },
          clear: {
            type: 'boolean',
            description: 'Clear buffer after reading (default: false)',
            default: false,
          },
        },
        required: ['session_id'],
      });
    });

    it('should have correct input schema for close_all_sessions tool', () => {
      const tools = generateToolDefinitions(serverConfig);
      const closeAllTool = tools.find(t => t.name === 'test_close_all_sessions');

      expect(closeAllTool).toBeDefined();
      expect(closeAllTool?.inputSchema).toEqual({
        type: 'object',
        properties: {},
      });
    });
  });

  describe('Different Server Configuration Scenarios', () => {
    it('should work with Kali Linux configuration', () => {
      const kaliConfig: LabConfig['server'] = {
        name: 'kali-server',
        version: '1.0.0',
        description: 'Kali server',
        toolPrefix: 'kali',
        targetName: 'Kali Linux',
        configKey: 'kali',
        envPrefix: 'KALI'
      };

      const tools = generateToolDefinitions(kaliConfig);
      
      expect(tools.map(t => t.name)).toEqual([
        'kali_info',
        'kali_run_command',
        'kali_interactive_session',
        'kali_background_session',
        'kali_session_command',
        'kali_list_sessions',
        'kali_close_session',
        'kali_get_session_output',
        'kali_close_all_sessions'
      ]);

      const infoTool = tools.find(t => t.name === 'kali_info');
      expect(infoTool?.description).toContain('Kali Linux');
    });

    it('should work with Minetest Client configuration', () => {
      const minetestConfig: LabConfig['server'] = {
        name: 'minetest-client',
        version: '1.0.0',
        description: 'Minetest client',
        toolPrefix: 'mc_client',
        targetName: 'Minetest Client',
        configKey: 'minetest-client',
        envPrefix: 'MINETEST_CLIENT'
      };

      const tools = generateToolDefinitions(minetestConfig);
      
      expect(tools.map(t => t.name)).toEqual([
        'mc_client_info',
        'mc_client_run_command',
        'mc_client_interactive_session',
        'mc_client_background_session',
        'mc_client_session_command',
        'mc_client_list_sessions',
        'mc_client_close_session',
        'mc_client_get_session_output',
        'mc_client_close_all_sessions'
      ]);

      const runCommandTool = tools.find(t => t.name === 'mc_client_run_command');
      expect(runCommandTool?.description).toContain('Minetest Client');
      expect(runCommandTool?.inputSchema.properties.command.description).toBe('Command to execute on Minetest Client');
    });

    it('should work with Victim container configuration', () => {
      const victimConfig: LabConfig['server'] = {
        name: 'victim-server',
        version: '1.0.0',
        description: 'Victim server',
        toolPrefix: 'victim',
        targetName: 'Victim Container',
        configKey: 'victim',
        envPrefix: 'VICTIM'
      };

      const tools = generateToolDefinitions(victimConfig);
      
      const backgroundSessionTool = tools.find(t => t.name === 'victim_background_session');
      expect(backgroundSessionTool?.description).toBe('Create a background session for long-running processes or interactive programs');
      
      const sessionCommandTool = tools.find(t => t.name === 'victim_session_command');
      expect(sessionCommandTool?.description).toBe('Execute a command in an existing persistent session');
    });
  });

  describe('Tool Structure Consistency', () => {
    const serverConfig: LabConfig['server'] = {
      name: 'test-server',
      version: '1.0.0',
      description: 'Test server',
      toolPrefix: 'test',
      targetName: 'Test Target',
      configKey: 'test-container',
      envPrefix: 'TEST'
    };

    it('should ensure all tools have required properties', () => {
      const tools = generateToolDefinitions(serverConfig);
      
      tools.forEach(tool => {
        expect(tool).toHaveProperty('name');
        expect(tool).toHaveProperty('description');
        expect(tool).toHaveProperty('inputSchema');
        
        expect(typeof tool.name).toBe('string');
        expect(typeof tool.description).toBe('string');
        expect(typeof tool.inputSchema).toBe('object');
        
        expect(tool.inputSchema.type).toBe('object');
        expect(tool.inputSchema).toHaveProperty('properties');
      });
    });

    it('should ensure all tools have unique names', () => {
      const tools = generateToolDefinitions(serverConfig);
      const names = tools.map(t => t.name);
      const uniqueNames = [...new Set(names)];
      
      expect(names.length).toBe(uniqueNames.length);
    });

    it('should ensure tool descriptions are descriptive', () => {
      const tools = generateToolDefinitions(serverConfig);
      
      tools.forEach(tool => {
        expect(tool.description.length).toBeGreaterThan(10);
        expect(tool.description).not.toBe('');
      });
    });
  });

  describe('Backward Compatibility', () => {
    it('should export empty default toolDefinitions for backward compatibility', () => {
      // This tests the export at the bottom of definitions.ts
      const { toolDefinitions } = require('../../src/tools/definitions.js');
      expect(Array.isArray(toolDefinitions)).toBe(true);
      expect(toolDefinitions).toHaveLength(0);
    });
  });
});