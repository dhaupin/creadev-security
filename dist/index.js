/**
 * @dhaupin/security
 *
 * Security utilities shared between weisync, migrare, and other projects.
 *
 * EXAMPLES:
 * ```typescript
 * import { RateLimiter, sanitizePath, createWaf } from '@dhaupin/security';
 *
 * // Rate limiting
 * const limiter = new RateLimiter({ maxRequests: 30, windowMs: 60000 });
 * const result = limiter.check('user-1', 'scan');
 *
 * // Input sanitization
 * const safe = sanitizePath('../etc/passwd');  // null
 * const safe = sanitizePath('my-project');       // 'my-project'
 *
 * // WAF
 * const waf = createWaf();
 * const check = waf.checkRequest(req);
 * ```
 *
 * ============================================================================
 */
export { RateLimiter, debounce, throttle, rafThrottle } from './rate-limit';
export { sanitizePath, sanitizeRepoName, sanitizeQueryParam, sanitizeInput, createWaf, getSecurityHeaders, getCsp, } from './sanitize';
