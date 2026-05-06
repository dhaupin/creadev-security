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

// ============================================================================
// PATH SANITIZATION
// ============================================================================

/** Sanitize file path - blocks directory traversal */
export function sanitizePath(path: string): string | null {
  if (!path || typeof path !== 'string') return null;
  
  // Normalize and check for traversal
  const normalized = path.replace(/\\/g, '/');
  
  // Block parent directory refs, absolute paths, Windows drives
  if (normalized.includes('..') || normalized.startsWith('/') || /^[a-zA-Z]:/.test(normalized)) {
    return null;
  }
  
  // Only allow safe characters
  if (!/^[a-zA-Z0-9_./\-]+$/.test(normalized)) {
    return null;
  }
  
  return normalized;
}

/** Sanitize repo/resource name */
export function sanitizeRepoName(name: string): string | null {
  if (!name || typeof name !== 'string') return null;
  
  // GitHub repo names: alphanumeric, hyphens, underscores, dots
  if (!/^[a-zA-Z0-9_.\-]+$/.test(name)) return null;
  if (name.length > 100) return null;
  
  return name;
}

/** Sanitize query parameter */
export function sanitizeQueryParam(value: string, allowed: string[]): string | null {
  if (!value || typeof value !== 'string') return null;
  if (allowed.includes(value)) return value;
  return null;
}

// ============================================================================
// INPUT VALIDATION
// ============================================================================

export interface ValidationResult {
  valid: boolean;
  sanitized: string | null;
  reason?: string;
}

/** Validate and sanitize generic input */
export function sanitizeInput(
  input: string,
  options: {
    maxLength?: number;
    pattern?: RegExp;
    allowEmpty?: boolean;
  } = {}
): ValidationResult {
  const { maxLength = 10000, pattern, allowEmpty = false } = options;
  
  if (!input) {
    return { valid: allowEmpty, sanitized: null, reason: 'Empty input' };
  }
  
  if (typeof input !== 'string') {
    return { valid: false, sanitized: null, reason: 'Not a string' };
  }
  
  if (input.length > maxLength) {
    return { valid: false, sanitized: null, reason: 'Exceeds max length' };
  }
  
  if (pattern && !pattern.test(input)) {
    return { valid: false, sanitized: null, reason: 'Pattern mismatch' };
  }
  
  return { valid: true, sanitized: input };
}

// ============================================================================
// WAF (Web Application Firewall)
// ============================================================================

export interface WafOptions {
  /** Max body size in bytes (default: 1MB) */
  maxBodySize?: number;
  /** Block XSS patterns in query (default: true) */
  blockXss?: boolean;
  /** Block SQL patterns (default: true) */
  blockSql?: boolean;
}

const XSS_PATTERNS = /(<script|javascript:|onerror=|onload=|eval\(|expression\(|alert\()/i;
const SQL_PATTERNS = /(\bunion\b|\bselect\b|\bdrop\b|\btable\b|--|\/\*|\*\/|xp_)/i;

/** Create WAF instance */
export function createWaf(options: WafOptions = {}) {
  const { maxBodySize = 1024 * 1024, blockXss = true, blockSql = true } = options;
  
  return {
    /** Check body size */
    checkBodySize(headers: { 'content-length'?: string }): boolean {
      const length = headers['content-length'];
      if (length) {
        const size = parseInt(length, 10);
        return !isNaN(size) && size <= maxBodySize;
      }
      return true;
    },
    
    /** Check for attack patterns in query string */
    checkQuery(query: string): { allowed: boolean; reason?: string } {
      if (!query) return { allowed: true };
      
      if (blockXss && XSS_PATTERNS.test(query)) {
        return { allowed: false, reason: 'XSS pattern detected' };
      }
      
      if (blockSql && SQL_PATTERNS.test(query)) {
        return { allowed: false, reason: 'SQL pattern detected' };
      }
      
      return { allowed: true };
    },
    
    /** Full request check */
    checkRequest(req: {
      headers: { 'content-length'?: string };
      url?: string;
    }): { allowed: boolean; reason?: string } {
      // Body size check
      if (!this.checkBodySize(req.headers)) {
        return { allowed: false, reason: 'Request too large' };
      }
      
      // Query check
      const url = req.url || '';
      const query = url.split('?')[1] || '';
      return this.checkQuery(query);
    },
  };
}

// ============================================================================
// SECURITY HEADERS
// ============================================================================

export type ResponseHeaders = Record<string, string | string[] | undefined>;

/** Get security headers */
export function getSecurityHeaders(): Record<string, string> {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
}

/** Get CSP header */
export function getCsp(options: {
  scriptSrc?: string[];
  styleSrc?: string[];
  imgSrc?: string[];
  connectSrc?: string[];
} = {}): string {
  const defaults = {
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    imgSrc: ["'self'", 'https:', 'data:'],
    connectSrc: ["'self'", 'https://api.github.com', 'https://localhost:*'],
  };
  
  const merged = {
    scriptSrc: [...defaults.scriptSrc, ...(options.scriptSrc || [])],
    styleSrc: [...defaults.styleSrc, ...(options.styleSrc || [])],
    imgSrc: [...defaults.imgSrc, ...(options.imgSrc || [])],
    connectSrc: [...defaults.connectSrc, ...(options.connectSrc || [])],
  };
  
  return [
    `default-src 'self'`,
    `script-src ${merged.scriptSrc.join(' ')}`,
    `style-src ${merged.styleSrc.join(' ')}`,
    `img-src ${merged.imgSrc.join(' ')}`,
    `connect-src ${merged.connectSrc.join(' ')}`,
    `frame-ancestors 'none'`,
  ].join('; ');
}