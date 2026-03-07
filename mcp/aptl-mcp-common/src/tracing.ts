/**
 * MCP tool call tracing for experiment instrumentation.
 *
 * Records every tool invocation with full arguments, responses,
 * timing, and error information as JSONL files for post-run analysis.
 */

import { appendFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

export interface ToolTrace {
  timestamp: string;
  server_name: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  response: unknown;
  duration_ms: number;
  success: boolean;
  error?: string;
}

export class ToolTracer {
  private readonly serverName: string;
  private readonly traceDir: string;
  private readonly tracePath: string;

  constructor(serverName: string, traceDir?: string) {
    this.serverName = serverName;
    this.traceDir = traceDir || process.env.APTL_TRACE_DIR || '.aptl/traces';
    this.tracePath = join(this.traceDir, `${serverName}.jsonl`);

    // Ensure trace directory exists
    if (!existsSync(this.traceDir)) {
      try {
        mkdirSync(this.traceDir, { recursive: true });
      } catch {
        console.error(`[Tracer] Could not create trace dir: ${this.traceDir}`);
      }
    }
  }

  /**
   * Wrap a tool handler call with tracing instrumentation.
   *
   * Records the call arguments, response, timing, and error status
   * to a per-server JSONL file.
   */
  async trace<T>(
    toolName: string,
    args: Record<string, unknown>,
    handler: () => Promise<T>,
  ): Promise<T> {
    const startTime = Date.now();
    let response: unknown = null;
    let success = true;
    let errorMsg: string | undefined;

    try {
      const result = await handler();
      response = result;
      return result;
    } catch (err) {
      success = false;
      errorMsg = err instanceof Error ? err.message : String(err);
      throw err;
    } finally {
      const trace: ToolTrace = {
        timestamp: new Date().toISOString(),
        server_name: this.serverName,
        tool_name: toolName,
        arguments: args,
        response: this.truncateResponse(response),
        duration_ms: Date.now() - startTime,
        success,
        ...(errorMsg !== undefined && { error: errorMsg }),
      };

      this.writeTrace(trace);
    }
  }

  /**
   * Truncate large responses to avoid bloating trace files.
   */
  private truncateResponse(response: unknown): unknown {
    const serialized = JSON.stringify(response);
    if (serialized && serialized.length > 50000) {
      return { _truncated: true, _length: serialized.length, _preview: serialized.slice(0, 2000) };
    }
    return response;
  }

  private writeTrace(trace: ToolTrace): void {
    try {
      const line = JSON.stringify(trace) + '\n';
      appendFileSync(this.tracePath, line, 'utf-8');
    } catch (err) {
      console.error(`[Tracer] Failed to write trace: ${err}`);
    }
  }

  /**
   * No-op flush — writes are synchronous via appendFileSync.
   */
  flush(): void {
    // Writes are already synchronous
  }
}
