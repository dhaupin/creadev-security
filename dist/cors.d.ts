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
/**
 * Build CORS headers
 *
 * @param source - Request (Web), Headers (Deno), or plain object (Node)
 * @param options - CORS options
 */
export declare function buildCorsHeaders(source: Request | Headers | Record<string, string>, options?: CorsOptions): Record<string, string>;
