/**
 * Endpoint URL resolution and validation for MCP API clients.
 *
 * Generic tool callers supply path-only endpoints; configured predefined
 * queries may use absolute URLs owned by lab config (empty baseUrl clients).
 */

export function isAbsoluteOrProtocolRelative(endpoint: string): boolean {
  return /^https?:\/\//i.test(endpoint) || endpoint.startsWith('//');
}

/** Reject caller-controlled absolute or relative paths for the generic API tool. */
export function assertPathOnlyEndpoint(endpoint: string): void {
  if (isAbsoluteOrProtocolRelative(endpoint)) {
    throw new Error('endpoint must be a path starting with /, not an absolute URL');
  }
  if (!endpoint.startsWith('/')) {
    throw new Error('endpoint must be a path starting with /');
  }
}

/**
 * Resolve endpoint + configured baseUrl into the URL that will receive auth headers.
 * Cross-origin destinations are rejected before auth is attached.
 */
export function resolveApiRequestUrl(endpoint: string, baseUrl: string): string {
  if (!baseUrl) {
    if (!isAbsoluteOrProtocolRelative(endpoint)) {
      throw new Error('endpoint must be an absolute URL when API baseUrl is not configured');
    }
    return endpoint.startsWith('//') ? `https:${endpoint}` : endpoint;
  }

  const configuredOrigin = new URL(baseUrl).origin;

  if (isAbsoluteOrProtocolRelative(endpoint)) {
    const absolute = endpoint.startsWith('//') ? `https:${endpoint}` : endpoint;
    const parsed = new URL(absolute);
    if (parsed.origin !== configuredOrigin) {
      throw new Error(
        `endpoint origin ${parsed.origin} does not match configured API origin ${configuredOrigin}`,
      );
    }
    return absolute;
  }

  if (!endpoint.startsWith('/')) {
    throw new Error('endpoint must be a path starting with /');
  }

  const resolved = new URL(endpoint, baseUrl);
  if (resolved.origin !== configuredOrigin) {
    throw new Error(
      `resolved URL origin ${resolved.origin} does not match configured API origin ${configuredOrigin}`,
    );
  }
  return resolved.href;
}
