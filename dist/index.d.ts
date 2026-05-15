/**
 * @creadev.org/security
 *
 * Security utilities shared between weisync, migrare, and other projects.
 *
 * EXAMPLES:
 * ```typescript
 * import { RateLimiter, sanitizePath, createWaf } from '@creadev.org/security';
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
export type { RateLimitOptions, CheckResult } from './rate-limit';
export { sanitizePath, sanitizeRepoName, sanitizeQueryParam, sanitizeInput, createWaf, getSecurityHeaders, getCsp, getClientIP, } from './sanitize';
export type { ValidationResult, WafOptions } from './sanitize';
export { validateUUID, validateUUIDs, validateBranchName, safeBranchName, validateFilePath, validateFilePaths, validateSHA, validateShortSHA, validateRepoFullName, parseRepoFullName, validateCommitMessage, } from './validation';
export { createFirewall, firewall, secureValidators, securityConfig, sanitizeText, sanitizeHtml, sanitizeUrl, sanitizeFilename, sanitizeJson, sanitize, isAreaActive, SECURITY_ACTIVE_AREAS, } from './firewall';
export type { FirewallConfig, FirewallInstance, FirewallResult, Threat, ThreatLevel, ThreatCategory, CustomPattern, InputType, } from './firewall';
export { buildCorsHeaders } from './cors';
export type { CorsOptions } from './cors';
