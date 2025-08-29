

import { WazuhConfig } from './config.js';

export interface WazuhAPIError extends Error {
  statusCode?: number;
  response?: any;
}

export interface AlertQuery {
  time_range?: string;
  min_level?: number;
  source_ip?: string;
  rule_id?: string;
  size?: number;
}

export interface LogQuery {
  time_range?: string;
  search_term?: string;
  source_ip?: string;
  log_level?: string;
  size?: number;
}

export interface Alert {
  timestamp: string;
  rule_id: string;
  level: number;
  description: string;
  source_ip?: string;
  agent_name?: string;
  full_log: string;
}

export interface LogEntry {
  timestamp: string;
  source_ip?: string;
  log_level?: string;
  message: string;
  location?: string;
}

export interface QueryResult<T> {
  count: number;
  data: T[];
}

/**
 * Wazuh Manager API client for authentication and rule management.
 * 
 * Features:
 * - JWT token authentication with automatic renewal
 * - Manager info retrieval
 * - Custom detection rule creation
 * - SSL verification bypass for lab environments
 * 
 * @example
 * const client = new WazuhAPIClient(config);
 * await client.authenticate();
 * const info = await client.getManagerInfo();
 */
export class WazuhAPIClient {
  private token: string | null = null;
  private tokenExpiry: number = 0;
  
  constructor(private config: WazuhConfig) {}



  /**
   * Authenticate with Wazuh API and get JWT token.
   * Automatically reuses valid tokens to avoid unnecessary API calls.
   * 
   * @throws {Error} If authentication fails
   */
  async authenticate(): Promise<void> {
    // Check if token is still valid
    if (this.token && Date.now() < this.tokenExpiry) {
      return;
    }

    const { manager } = this.config.wazuh;
    const url = `${manager.protocol}://${manager.host}:${manager.api_port}/security/user/authenticate`;
    
    const auth = Buffer.from(`${manager.api_username}:${manager.api_password}`).toString('base64');
    
    try {
      // Disable SSL verification if configured
      if (!manager.verify_ssl) {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      }
      
      const options = {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json'
        }
      };
      const response = await fetch(url, options);

      if (!response.ok) {
        throw new Error(`Authentication failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      this.token = data.data.token;
      // Set token expiry to 15 minutes from now
      this.tokenExpiry = Date.now() + (15 * 60 * 1000);
      
      console.error('[MCP-Blue] Successfully authenticated with Wazuh API');
    } catch (error) {
      throw new Error(`Failed to authenticate with Wazuh API: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get information about Wazuh Manager including version and cluster details.
   * 
   * @returns Manager information object
   * @throws {Error} If request fails or authentication required
   */
  async getManagerInfo(): Promise<any> {
    await this.authenticate();
    
    const { manager } = this.config.wazuh;
    const url = `${manager.protocol}://${manager.host}:${manager.api_port}/manager/info`;
    
    try {
      const options: any = {
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json'
        }
      };
      if (!manager.verify_ssl) {

      }
      const response = await fetch(url, options);

      if (!response.ok) {
        throw new Error(`Manager info request failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      throw new Error(`Failed to get manager info: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Create a custom detection rule on the Wazuh Manager.
   * 
   * @param ruleXML - Complete XML rule definition
   * @param filename - Rule file name (default: 'aptl_custom_rules.xml')
   * @returns Rule creation response
   * @throws {Error} If rule creation fails
   * 
   * @example
   * const ruleXML = '<rule id="100001" level="10">Custom rule</rule>';
   * await client.createRule(ruleXML, 'custom_rules.xml');
   */
  async createRule(ruleXML: string, filename: string = 'aptl_custom_rules.xml'): Promise<any> {
    await this.authenticate();
    
    const { manager } = this.config.wazuh;
    const url = `${manager.protocol}://${manager.host}:${manager.api_port}/rules/files/${filename}`;
    
    try {
      const options: any = {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/xml'
        },
        body: ruleXML
      };
      if (!manager.verify_ssl) {

      }
      const response = await fetch(url, options);

      if (!response.ok) {
        throw new Error(`Rule creation failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      throw new Error(`Failed to create rule: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

/**
 * Wazuh Indexer (OpenSearch) client for searching alerts and logs.
 * 
 * Features:
 * - Alert searching with filtering and sorting
 * - Raw log searching across archives
 * - Cluster health monitoring
 * - Query building for OpenSearch syntax
 * 
 * @example
 * const client = new WazuhIndexerClient(config);
 * const alerts = await client.searchAlerts({ time_range: '1h', min_level: 5 });
 */
export class WazuhIndexerClient {
  constructor(private config: WazuhConfig) {}

  /**
   * Search alerts in Wazuh indices with filtering and sorting.
   * 
   * @param query - Alert query parameters
   * @returns Search results with count and formatted alert data
   * @throws {Error} If search request fails
   * 
   * @example
   * const results = await client.searchAlerts({
   *   time_range: '24h',
   *   min_level: 10,
   *   source_ip: '172.20.0.30'
   * });
   */
  async searchAlerts(query: AlertQuery): Promise<QueryResult<Alert>> {
    const { indexer } = this.config.wazuh;
    const url = `${indexer.protocol}://${indexer.host}:${indexer.port}/wazuh-alerts-4.x-*/_search`;
    
    const searchQuery = this.buildAlertQuery(query);
    const auth = Buffer.from(`${indexer.username}:${indexer.password}`).toString('base64');
    
    try {
      const options: any = {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(searchQuery)
      };
      if (!indexer.verify_ssl) {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      }
      const response = await fetch(url, options);

      if (!response.ok) {
        throw new Error(`Alert search failed: ${response.status}`);
      }

      const data = await response.json();
      return {
        count: data.hits.total.value || 0,
        data: data.hits.hits.map((hit: any) => this.formatAlert(hit._source))
      };
    } catch (error) {
      throw new Error(`Failed to search alerts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Search raw logs in Wazuh archives before rule processing.
   * 
   * @param query - Log query parameters
   * @returns Search results with count and formatted log entries
   * @throws {Error} If search request fails
   * 
   * @example
   * const results = await client.searchLogs({
   *   search_term: 'failed login',
   *   time_range: '6h'
   * });
   */
  async searchLogs(query: LogQuery): Promise<QueryResult<LogEntry>> {
    const { indexer } = this.config.wazuh;
    const url = `${indexer.protocol}://${indexer.host}:${indexer.port}/wazuh-archives-4.x-*/_search`;
    
    const searchQuery = this.buildLogQuery(query);
    const auth = Buffer.from(`${indexer.username}:${indexer.password}`).toString('base64');
    
    try {
      const options: any = {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(searchQuery)
      };
      if (!indexer.verify_ssl) {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      }
      const response = await fetch(url, options);

      if (!response.ok) {
        throw new Error(`Log search failed: ${response.status}`);
      }

      const data = await response.json();
      return {
        count: data.hits.total.value || 0,
        data: data.hits.hits.map((hit: any) => this.formatLog(hit._source))
      };
    } catch (error) {
      throw new Error(`Failed to search logs: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get cluster health status from Wazuh Indexer.
   * 
   * @returns Cluster health information including status and node count
   * @throws {Error} If health check fails
   * 
   * @example
   * const health = await client.getClusterHealth();
   * console.log(`Cluster status: ${health.status}`);
   */
  async getClusterHealth(): Promise<any> {
    const { indexer } = this.config.wazuh;
    const url = `${indexer.protocol}://${indexer.host}:${indexer.port}/_cluster/health`;
    
    const auth = Buffer.from(`${indexer.username}:${indexer.password}`).toString('base64');
    
    try {
      const options: any = {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json'
        }
      };
      if (!indexer.verify_ssl) {
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      }
      const response = await fetch(url, options);

      if (!response.ok) {
        throw new Error(`Cluster health request failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      throw new Error(`Failed to get cluster health: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Build OpenSearch query for alert searching.
   * Constructs bool query with filters for time range, level, source IP, and rule ID.
   * 
   * @param query - Alert query parameters
   * @returns OpenSearch query object
   * @private
   */
  private buildAlertQuery(query: AlertQuery): any {
    const filters: any[] = [];
    
    // Time range filter
    if (query.time_range) {
      filters.push({
        range: {
          timestamp: {
            gte: `now-${query.time_range}`
          }
        }
      });
    }
    
    // Minimum level filter
    if (query.min_level) {
      filters.push({
        range: {
          'rule.level': {
            gte: query.min_level
          }
        }
      });
    }
    
    // Source IP filter
    if (query.source_ip) {
      filters.push({
        term: {
          'data.srcip': query.source_ip
        }
      });
    }
    
    // Rule ID filter
    if (query.rule_id) {
      filters.push({
        term: {
          'rule.id': query.rule_id
        }
      });
    }

    return {
      query: {
        bool: {
          filter: filters
        }
      },
      sort: [
        {
          timestamp: {
            order: 'desc'
          }
        }
      ],
      size: query.size || 100
    };
  }

  /**
   * Build OpenSearch query for log searching.
   * Constructs bool query with filters and text matching.
   * 
   * @param query - Log query parameters
   * @returns OpenSearch query object
   * @private
   */
  private buildLogQuery(query: LogQuery): any {
    const filters: any[] = [];
    const must: any[] = [];
    
    // Time range filter
    if (query.time_range) {
      filters.push({
        range: {
          timestamp: {
            gte: `now-${query.time_range}`
          }
        }
      });
    }
    
    // Search term
    if (query.search_term) {
      must.push({
        match: {
          full_log: query.search_term
        }
      });
    }
    
    // Source IP filter
    if (query.source_ip) {
      filters.push({
        term: {
          'agent.ip': query.source_ip
        }
      });
    }
    
    // Log level filter
    if (query.log_level) {
      filters.push({
        term: {
          log_level: query.log_level
        }
      });
    }

    const boolQuery: any = {};
    if (filters.length > 0) boolQuery.filter = filters;
    if (must.length > 0) boolQuery.must = must;

    return {
      query: {
        bool: boolQuery
      },
      sort: [
        {
          timestamp: {
            order: 'desc'
          }
        }
      ],
      size: query.size || 100
    };
  }

  /**
   * Format alert data for consistent output structure.
   * 
   * @param source - Raw alert source from OpenSearch
   * @returns Formatted alert object
   * @private
   */
  private formatAlert(source: any): Alert {
    return {
      timestamp: source.timestamp || source['@timestamp'],
      rule_id: source.rule?.id || 'unknown',
      level: source.rule?.level || 0,
      description: source.rule?.description || 'No description',
      source_ip: source.data?.srcip,
      agent_name: source.agent?.name,
      full_log: source.full_log || source.data?.log || ''
    };
  }

  /**
   * Format log data for consistent output structure.
   * 
   * @param source - Raw log source from OpenSearch
   * @returns Formatted log entry object
   * @private
   */
  private formatLog(source: any): LogEntry {
    return {
      timestamp: source.timestamp || source['@timestamp'],
      source_ip: source.agent?.ip,
      log_level: source.log_level,
      message: source.full_log || source.message || '',
      location: source.location
    };
  }
}