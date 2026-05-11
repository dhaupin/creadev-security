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
export class RateLimiter {
  private limits = new Map<string, { count: number; resetAt: number }>();
  private options: RateLimitOptions;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: RateLimitOptions) {
    this.options = { ...options, cleanupIntervalMs: options.cleanupIntervalMs ?? 60000 };
    this.startCleanup();
  }

  private startCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.limits) {
        if (now > entry.resetAt) {
          this.limits.delete(key);
        }
      }
    }, this.options.cleanupIntervalMs ?? 60000);
  }

  /** Stop cleanup timer and clear all limits */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.limits.clear();
  }

  /** Reset limit for a key */
  check(key: string, endpointId?: string): CheckResult {
    const now = Date.now();
    const compositeKey = endpointId ? `${endpointId}:${key}` : key;
    const entry = this.limits.get(compositeKey);

    // No existing record - allow
    if (!entry) {
      const resetAt = now + this.options.windowMs;
      this.limits.set(compositeKey, { count: 1, resetAt });
      return {
        allowed: true,
        remaining: this.options.maxRequests - 1,
        retryAfter: null,
        resetAt,
      };
    }

    // Check if window expired
    if (now > entry.resetAt) {
      const resetAt = now + this.options.windowMs;
      this.limits.set(compositeKey, { count: 1, resetAt });
      return {
        allowed: true,
        remaining: this.options.maxRequests - 1,
        retryAfter: null,
        resetAt,
      };
    }

    // Within window - check limit
    if (entry.count >= this.options.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        retryAfter: Math.ceil((entry.resetAt - now) / 1000),
        resetAt: entry.resetAt,
      };
    }

    entry.count++;
    return {
      allowed: true,
      remaining: this.options.maxRequests - entry.count,
      retryAfter: null,
      resetAt: entry.resetAt,
    };
  }

  /** Reset limit for a key */
  reset(key: string, endpointId?: string): void {
    const compositeKey = endpointId ? `${endpointId}:${key}` : key;
    this.limits.delete(compositeKey);
  }

  /** Get remaining for a key */
  remaining(key: string, endpointId?: string): number {
    const compositeKey = endpointId ? `${endpointId}:${key}` : key;
    const entry = this.limits.get(compositeKey);
    if (!entry || Date.now() > entry.resetAt) {
      return this.options.maxRequests;
    }
    return Math.max(0, this.options.maxRequests - entry.count);
  }
}

// ============================================================================
// UI Utilities (from weisync)
// ============================================================================

export type AnyFn = (...args: unknown[]) => void;

/**
 * Debounce - wait for calls to settle before executing.
 * Best for: search input, autosave, form validation.
 */
export function debounce<T extends AnyFn>(fn: T, waitMs = 0) {
  let t: ReturnType<typeof setTimeout> | undefined;

  const debounced = (...args: Parameters<T>) => {
    if (t) clearTimeout(t);
    t = setTimeout(() => fn(...args), waitMs);
  };

  debounced.cancel = () => {
    if (t) clearTimeout(t);
    t = undefined;
  };

  return debounced as T & { cancel: () => void };
}

/**
 * Throttle - rate-limit calls to a fixed interval.
 */
export function throttle<T extends AnyFn>(fn: T, waitMs = 0) {
  let t: ReturnType<typeof setTimeout> | undefined;
  let lastArgs: Parameters<T> | undefined;

  const throttled = (...args: Parameters<T>) => {
    lastArgs = args;
    if (!t) {
      fn(...args);
      t = setTimeout(() => {
        t = undefined;
        if (lastArgs) fn(...lastArgs);
      }, waitMs);
    }
  };

  throttled.cancel = () => {
    if (t) clearTimeout(t);
    t = undefined;
    lastArgs = undefined;
  };

  return throttled as T & { cancel: () => void };
}

/**
 * RAF throttle - rate-limit to animation frame.
 */
export function rafThrottle<T extends AnyFn>(fn: T) {
  let running = false;
  let queued = false;
  let lastArgs: Parameters<T> | undefined;

  const raf = () => {
    if (!queued) return;
    queued = false;
    running = true;
    fn(...lastArgs!);
    requestAnimationFrame(() => {
      running = false;
      if (queued) raf();
    });
  };

  const throttled = (...args: Parameters<T>) => {
    lastArgs = args;
    if (running) {
      queued = true;
    } else {
      raf();
    }
  };

  throttled.cancel = () => {
    running = false;
    queued = false;
  };

  return throttled as T & { cancel: () => void };
}