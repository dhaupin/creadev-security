/**
 * ============================================================================
 * Rate Limiting - Node.js Compatible
 * ============================================================================
 *
 * PURPOSE:
 * In-memory rate limiting with per-key limits.
 *
 * USAGE:
 * ```typescript
 * import { RateLimiter } from '@creadev.org/security/rate-limit';
 *
 * const limiter = new RateLimiter({ maxRequests: 30, windowMs: 60000 });
 *
 * // Check if allowed
 * const result = limiter.check('user-123', 'auth-status');
 * if (!result.allowed) {
 *   console.log('Retry after', result.retryAfter);
 * }
 * ```
 *
 * ============================================================================
 */
export interface RateLimitOptions {
    /** Max requests per window */
    maxRequests: number;
    /** Window size in ms */
    windowMs: number;
    /** Cleanup interval (default: 60000) */
    cleanupIntervalMs?: number;
}
export interface CheckResult {
    allowed: boolean;
    remaining: number;
    retryAfter: number | null;
    resetAt: number;
}
/** In-memory rate limiter */
export declare class RateLimiter {
    private limits;
    private options;
    private cleanupTimer;
    constructor(options: RateLimitOptions);
    private startCleanup;
    /** Stop cleanup timer and clear all limits */
    destroy(): void;
    /** Reset limit for a key */
    check(key: string, endpointId?: string): CheckResult;
    /** Reset limit for a key */
    reset(key: string, endpointId?: string): void;
    /** Get remaining for a key */
    remaining(key: string, endpointId?: string): number;
}
export type AnyFn = (...args: unknown[]) => void;
/**
 * Debounce - wait for calls to settle before executing.
 * Best for: search input, autosave, form validation.
 */
export declare function debounce<T extends AnyFn>(fn: T, waitMs?: number): T & {
    cancel: () => void;
};
/**
 * Throttle - rate-limit calls to a fixed interval.
 */
export declare function throttle<T extends AnyFn>(fn: T, waitMs?: number): T & {
    cancel: () => void;
};
/**
 * RAF throttle - rate-limit to animation frame.
 */
export declare function rafThrottle<T extends AnyFn>(fn: T): T & {
    cancel: () => void;
};
