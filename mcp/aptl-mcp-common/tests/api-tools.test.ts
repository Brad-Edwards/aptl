import { describe, it, expect } from 'vitest';
import { generateAPIToolDefinitions } from '../src/tools/api-definitions.js';
import { generateAPIToolHandlers } from '../src/tools/api-handlers.js';

describe('generateAPIToolDefinitions', () => {
  const mockServerConfig = {
    toolPrefix: 'wazuh',
    targetName: 'Wazuh SIEM'
  };

  it('generates basic API tools', () => {
    const tools = generateAPIToolDefinitions(mockServerConfig);
    
    expect(tools).toHaveLength(2);
    expect(tools[0].name).toBe('wazuh_api_call');
    expect(tools[1].name).toBe('wazuh_api_info');
    expect(tools[0].description).toContain('Wazuh SIEM');
  });

  it('generates predefined query tools', () => {
    const queries = {
      recent_alerts: {
        endpoint: '/api/alerts',
        method: 'GET' as const,
        description: 'Get recent alerts'
      },
      search_logs: {
        endpoint: '/api/search',
        method: 'POST' as const,
        description: 'Search log data'
      }
    };
    
    const tools = generateAPIToolDefinitions(mockServerConfig, queries);
    
    expect(tools).toHaveLength(4); // 2 basic + 2 queries
    expect(tools[2].name).toBe('wazuh_recent_alerts');
    expect(tools[3].name).toBe('wazuh_search_logs');
    expect(tools[2].description).toBe('Get recent alerts');
  });

  it('works with different server configs', () => {
    const splunkConfig = {
      toolPrefix: 'splunk',
      targetName: 'Splunk Enterprise'
    };
    
    const tools = generateAPIToolDefinitions(splunkConfig);
    
    expect(tools[0].name).toBe('splunk_api_call');
    expect(tools[0].description).toContain('Splunk Enterprise');
  });
});

describe('generateAPIToolHandlers', () => {
  const mockServerConfig = {
    toolPrefix: 'wazuh',
    targetName: 'Wazuh SIEM'
  };

  it('generates handler map with correct tool names', () => {
    const handlers = generateAPIToolHandlers(mockServerConfig);
    
    expect(handlers['wazuh_api_call']).toBeDefined();
    expect(handlers['wazuh_api_info']).toBeDefined();
    expect(typeof handlers['wazuh_api_call']).toBe('function');
  });

  it('generates predefined query handlers', () => {
    const queries = {
      recent_alerts: {
        endpoint: '/api/alerts',
        method: 'GET' as const,
        description: 'Get recent alerts'
      }
    };
    
    const handlers = generateAPIToolHandlers(mockServerConfig, queries);
    
    expect(handlers['wazuh_recent_alerts']).toBeDefined();
    expect(typeof handlers['wazuh_recent_alerts']).toBe('function');
  });

  it('works with different server configs', () => {
    const elasticConfig = {
      toolPrefix: 'elastic',
      targetName: 'Elasticsearch'
    };
    
    const handlers = generateAPIToolHandlers(elasticConfig);
    
    expect(handlers['elastic_api_call']).toBeDefined();
    expect(handlers['elastic_api_info']).toBeDefined();
  });
});