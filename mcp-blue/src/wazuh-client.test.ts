import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { WazuhAPIClient, WazuhIndexerClient } from './wazuh-client.js';
import { WazuhConfig } from './config.js';

// Mock fetch globally
global.fetch = vi.fn();

describe('WazuhAPIClient', () => {
  let client: WazuhAPIClient;
  let mockConfig: WazuhConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    
    mockConfig = {
      wazuh: {
        manager: {
          host: '172.20.0.10',
          api_port: 55000,
          protocol: 'https',
          api_username: 'admin',
          api_password: 'password',
          verify_ssl: false
        },
        indexer: {
          host: '172.20.0.12',
          port: 9200,
          protocol: 'https',
          username: 'admin',
          password: 'password',
          verify_ssl: false
        },
        dashboard: {
          host: '172.20.0.11',
          port: 443,
          protocol: 'https',
          url: 'https://localhost:443'
        }
      },
      network: { lab_subnet: '172.20.0.0/16', gateway: '172.20.0.1' },
      query_limits: { max_alerts_per_query: 1000, max_time_range_days: 30, rate_limit_per_minute: 10 },
      mcp: { server_name: 'test-server' }
    };

    client = new WazuhAPIClient(mockConfig);
  });

  afterEach(() => {
    // Reset NODE_TLS_REJECT_UNAUTHORIZED
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  });

  describe('authenticate', () => {
    it('should authenticate successfully and store token', async () => {
      const mockToken = 'test-jwt-token';
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { token: mockToken } })
      } as Response);

      await client.authenticate();

      expect(fetch).toHaveBeenCalledWith(
        'https://172.20.0.10:55000/security/user/authenticate',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Authorization': expect.stringContaining('Basic'),
            'Content-Type': 'application/json'
          })
        })
      );

      // Token should be stored internally
      expect((client as any).token).toBe(mockToken);
    });

    it('should reuse valid token', async () => {
      const mockToken = 'test-jwt-token';
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { token: mockToken } })
      } as Response);

      await client.authenticate();
      vi.clearAllMocks();
      
      // Second call should not fetch again
      await client.authenticate();
      expect(fetch).not.toHaveBeenCalled();
    });

    it('should handle authentication failure', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized'
      } as Response);

      await expect(client.authenticate()).rejects.toThrow('Authentication failed: 401 Unauthorized');
    });

    it('should disable SSL verification when configured', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { token: 'token' } })
      } as Response);

      await client.authenticate();
      
      expect(process.env.NODE_TLS_REJECT_UNAUTHORIZED).toBe('0');
    });
  });

  describe('getManagerInfo', () => {
    it('should get manager info successfully', async () => {
      const mockInfo = { version: '4.5.0', cluster: 'aptl-cluster' };
      
      // Mock authentication
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { token: 'test-token' } })
      } as Response);

      // Mock manager info
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => mockInfo
      } as Response);

      const result = await client.getManagerInfo();
      
      expect(result).toEqual(mockInfo);
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(fetch).toHaveBeenLastCalledWith(
        'https://172.20.0.10:55000/manager/info',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      );
    });

    it('should handle manager info request failure', async () => {
      // Mock authentication
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { token: 'test-token' } })
      } as Response);

      // Mock failed manager info
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: false,
        status: 500
      } as Response);

      await expect(client.getManagerInfo()).rejects.toThrow('Manager info request failed: 500');
    });
  });

  describe('createRule', () => {
    it('should create rule successfully', async () => {
      const ruleXML = '<rule id="100001" level="5">Test rule</rule>';
      const mockResponse = { status: 'success', message: 'Rule created' };

      // Mock authentication
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { token: 'test-token' } })
      } as Response);

      // Mock rule creation
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse
      } as Response);

      const result = await client.createRule(ruleXML, 'custom_rules.xml');
      
      expect(result).toEqual(mockResponse);
      expect(fetch).toHaveBeenLastCalledWith(
        'https://172.20.0.10:55000/rules/files/custom_rules.xml',
        expect.objectContaining({
          method: 'PUT',
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token',
            'Content-Type': 'application/xml'
          }),
          body: ruleXML
        })
      );
    });

    it('should handle rule creation failure', async () => {
      // Mock authentication
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { token: 'test-token' } })
      } as Response);

      // Mock failed rule creation
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: false,
        status: 400
      } as Response);

      await expect(client.createRule('<rule>', 'test.xml')).rejects.toThrow('Rule creation failed: 400');
    });
  });
});

describe('WazuhIndexerClient', () => {
  let client: WazuhIndexerClient;
  let mockConfig: WazuhConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    
    mockConfig = {
      wazuh: {
        manager: {
          host: '172.20.0.10',
          api_port: 55000,
          protocol: 'https',
          api_username: 'admin',
          api_password: 'password',
          verify_ssl: false
        },
        indexer: {
          host: '172.20.0.12',
          port: 9200,
          protocol: 'https',
          username: 'admin',
          password: 'password',
          verify_ssl: false
        },
        dashboard: {
          host: '172.20.0.11',
          port: 443,
          protocol: 'https',
          url: 'https://localhost:443'
        }
      },
      network: { lab_subnet: '172.20.0.0/16', gateway: '172.20.0.1' },
      query_limits: { max_alerts_per_query: 1000, max_time_range_days: 30, rate_limit_per_minute: 10 },
      mcp: { server_name: 'test-server' }
    };

    client = new WazuhIndexerClient(mockConfig);
  });

  afterEach(() => {
    delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  });

  describe('searchAlerts', () => {
    it('should search alerts successfully', async () => {
      const mockAlerts = {
        hits: {
          total: { value: 2 },
          hits: [
            {
              _source: {
                timestamp: '2024-01-01T10:00:00Z',
                rule: { id: '1001', level: 5, description: 'Test alert 1' },
                data: { srcip: '172.20.0.30' },
                agent: { name: 'victim-agent' },
                full_log: 'Log entry 1'
              }
            },
            {
              _source: {
                '@timestamp': '2024-01-01T10:01:00Z',
                rule: { id: '1002', level: 10, description: 'Test alert 2' },
                data: { srcip: '172.20.0.31' },
                agent: { name: 'kali-agent' },
                full_log: 'Log entry 2'
              }
            }
          ]
        }
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => mockAlerts
      } as Response);

      const result = await client.searchAlerts({
        time_range: '1h',
        min_level: 5
      });

      expect(result.count).toBe(2);
      expect(result.data).toHaveLength(2);
      expect(result.data[0].rule_id).toBe('1001');
      expect(result.data[1].rule_id).toBe('1002');
      
      expect(fetch).toHaveBeenCalledWith(
        'https://172.20.0.12:9200/wazuh-alerts-4.x-*/_search',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ=',
            'Content-Type': 'application/json'
          })
        })
      );
      
      // Check that the request body contains the expected query structure
      const callArgs = vi.mocked(fetch).mock.calls[0];
      const body = JSON.parse(callArgs[1]?.body as string);
      expect(body.query.bool.filter).toContainEqual({
        range: { timestamp: { gte: 'now-1h' } }
      });
      expect(body.query.bool.filter).toContainEqual({
        range: { 'rule.level': { gte: 5 } }
      });
    });

    it('should handle search failure', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: false,
        status: 503
      } as Response);

      await expect(client.searchAlerts({})).rejects.toThrow('Alert search failed: 503');
    });

    it('should format alerts correctly', async () => {
      const mockAlerts = {
        hits: {
          total: { value: 1 },
          hits: [
            {
              _source: {
                '@timestamp': '2024-01-01T10:00:00Z',
                rule: { id: '1001', level: 5, description: 'Test alert' },
                data: { srcip: '172.20.0.30', log: 'Alternative log field' },
                agent: { name: 'test-agent' }
              }
            }
          ]
        }
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => mockAlerts
      } as Response);

      const result = await client.searchAlerts({});

      expect(result.data[0]).toEqual({
        timestamp: '2024-01-01T10:00:00Z',
        rule_id: '1001',
        level: 5,
        description: 'Test alert',
        source_ip: '172.20.0.30',
        agent_name: 'test-agent',
        full_log: 'Alternative log field'
      });
    });
  });

  describe('searchLogs', () => {
    it('should search logs successfully', async () => {
      const mockLogs = {
        hits: {
          total: { value: 1 },
          hits: [
            {
              _source: {
                timestamp: '2024-01-01T10:00:00Z',
                agent: { ip: '172.20.0.20' },
                log_level: 'error',
                full_log: 'Error message',
                location: '/var/log/app.log'
              }
            }
          ]
        }
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => mockLogs
      } as Response);

      const result = await client.searchLogs({
        search_term: 'error',
        time_range: '1h'
      });

      expect(result.count).toBe(1);
      expect(result.data[0]).toEqual({
        timestamp: '2024-01-01T10:00:00Z',
        source_ip: '172.20.0.20',
        log_level: 'error',
        message: 'Error message',
        location: '/var/log/app.log'
      });
    });

    it('should build log query with search terms', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ hits: { total: { value: 0 }, hits: [] } })
      } as Response);

      await client.searchLogs({
        search_term: 'test search',
        source_ip: '172.20.0.30',
        log_level: 'info'
      });

      const callArgs = vi.mocked(fetch).mock.calls[0];
      const body = JSON.parse(callArgs[1]?.body as string);
      
      expect(body.query.bool.must).toContainEqual({
        match: { full_log: 'test search' }
      });
      expect(body.query.bool.filter).toContainEqual({
        term: { 'agent.ip': '172.20.0.30' }
      });
      expect(body.query.bool.filter).toContainEqual({
        term: { log_level: 'info' }
      });
    });
  });

  describe('getClusterHealth', () => {
    it('should get cluster health successfully', async () => {
      const mockHealth = {
        cluster_name: 'wazuh-cluster',
        status: 'green',
        number_of_nodes: 3
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: async () => mockHealth
      } as Response);

      const result = await client.getClusterHealth();

      expect(result).toEqual(mockHealth);
      expect(fetch).toHaveBeenCalledWith(
        'https://172.20.0.12:9200/_cluster/health',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': expect.stringContaining('Basic')
          })
        })
      );
    });

    it('should handle cluster health request failure', async () => {
      vi.mocked(fetch).mockResolvedValueOnce({
        ok: false,
        status: 503
      } as Response);

      await expect(client.getClusterHealth()).rejects.toThrow('Cluster health request failed: 503');
    });
  });
});