/**
 * ============================================================================
 * Input Sanitization - Node.js Compatible
 * ============================================================================
 *
 * PURPOSE:
 * Input validation and sanitization for HTTP servers.
 * Blocks attacks: path traversal, XSS, injection.
 *
 * USAGE:
 * ```typescript
 * import { sanitizePath, sanitizeInput, createWaf } from '@dhaupin/security/sanitize';
 *
 * // Path traversal check
 * const path = sanitizePath(userInput);
 * if (!path) throw new Error('Invalid path');
 *
 * // Full WAF
 * const waf = createWaf();
 * const result = waf.check(req);
 * if (!result.allowed) throw new Error('Blocked');
 * ```
 *
 * ============================================================================
 */
/** Sanitize file path - blocks directory traversal */
export declare function sanitizePath(path: string): string | null;
/** Sanitize repo/resource name */
export declare function sanitizeRepoName(name: string): string | null;
/** Sanitize query parameter */
export declare function sanitizeQueryParam(value: string, allowed: string[]): string | null;
export interface ValidationResult {
    valid: boolean;
    sanitized: string | null;
    reason?: string;
}
/** Validate and sanitize generic input */
export declare function sanitizeInput(input: string, options?: {
    maxLength?: number;
    pattern?: RegExp;
    allowEmpty?: boolean;
}): ValidationResult;
export interface WafOptions {
    /** Max body size in bytes (default: 1MB) */
    maxBodySize?: number;
    /** Block XSS patterns in query (default: true) */
    blockXss?: boolean;
    /** Block SQL patterns (default: true) */
    blockSql?: boolean;
}
/** Create WAF instance */
export declare function createWaf(options?: WafOptions): {
    /** Check body size */
    checkBodySize(headers: {
        "content-length"?: string;
    }): boolean;
    /** Check for attack patterns in query string */
    checkQuery(query: string): {
        allowed: boolean;
        reason?: string;
    };
    /** Full request check */
    checkRequest(req: {
        headers: {
            "content-length"?: string;
        };
        url?: string;
    }): {
        allowed: boolean;
        reason?: string;
    };
};
export type ResponseHeaders = Record<string, string | string[] | undefined>;
/** Get security headers */
export declare function getSecurityHeaders(): Record<string, string>;
/** Get CSP header */
export declare function getCsp(options?: {
    scriptSrc?: string[];
    styleSrc?: string[];
    imgSrc?: string[];
    connectSrc?: string[];
}): string;
