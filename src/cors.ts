/**
 * ============================================================================
 * CORS Headers Builder
 * ============================================================================
 *
 * PURPOSE:
 * Build CORS headers based on request origin.
 * Works in: Browser, Deno, Cloudflare Workers, Node.js
 *
 * USAGE:
 * ```typescript
 * import { buildCorsHeaders } from '@creadev.org/security';
 * 
 * // Web/Deno (from Request)
 * const headers = buildCorsHeaders(request);
 * 
 * // Node.js (from headers object)
 * const headers = buildCorsHeaders({ 'origin': 'https://example.com' });
 * ```
 * ============================================================================
 */

export interface CorsOptions {
  /** Allowed origins (comma-separated or array) */
  allowedOrigins?: string;
  /** Additional headers to allow */
  allowHeaders?: string;
  /** Methods to allow */
  allowMethods?: string | string[];
}

/** Default headers */
const DEFAULT_ALLOW_HEADERS = [
  'authorization',
  'x-client-info',
  'apikey',
  'content-type',
  'x-supabase-client-platform',
  'x-supabase-client-platform-version',
].join(', ');

const DEFAULT_ALLOW_METHODS = 'GET, POST, PUT, DELETE, PATCH, OPTIONS';

/**
 * Get origin from Request (Web) or Headers object (Node)
 */
function getOrigin(source: Request | Headers | Record<string, string> | undefined): string | null {
  if (!source) return null;
  
  // Web Request
  if (source instanceof Request) {
    return source.headers.get('origin');
  }
  
  // Headers object
  if (source instanceof Headers) {
    return source.get('origin');
  }
  
  // Plain object (Node)
  const lowerKey = Object.keys(source).find(k => k.toLowerCase() === 'origin');
  return lowerKey ? source[lowerKey] : null;
}

/**
 * Convert allowMethods to string
 */
function methodsToString(methods: string | string[] | undefined): string {
  if (!methods) return DEFAULT_ALLOW_METHODS;
  if (Array.isArray(methods)) return methods.join(', ');
  return methods;
}

/**
 * Build CORS headers
 * 
 * @param source - Request (Web), Headers (Deno), or plain object (Node)
 * @param options - CORS options
 */
export function buildCorsHeaders(
  source: Request | Headers | Record<string, string>,
  options: CorsOptions = {}
): Record<string, string> {
  const { allowedOrigins, allowHeaders } = options;
  const allowMethods = methodsToString(options.allowMethods);
  
  const origin = getOrigin(source);
  
  const defaultHeaders: Record<string, string> = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': allowHeaders ?? DEFAULT_ALLOW_HEADERS,
    'Access-Control-Allow-Methods': allowMethods,
  };
  
  // No allowed origins set - return wide open (backwards compatible)
  if (!allowedOrigins || allowedOrigins === '*') {
    return defaultHeaders;
  }
  
  // Parse allowed origins
  const allowedList = Array.isArray(allowedOrigins) 
    ? allowedOrigins 
    : allowedOrigins.split(',').map(o => o.trim());
  
  // Check if origin is allowed
  const isAllowed = origin && allowedList.includes(origin);
  
  if (isAllowed && origin) {
    return {
      ...defaultHeaders,
      'Access-Control-Allow-Origin': origin,
    };
  }
  
  // Origin not allowed - block via 'null' origin
  return {
    ...defaultHeaders,
    'Access-Control-Allow-Origin': 'null',
  };
}
