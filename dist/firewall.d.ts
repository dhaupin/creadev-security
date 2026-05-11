/**
 * ============================================================================
 * Full Firewall - Input Processing & Threat Detection
 * ============================================================================
 *
 * PURPOSE:
 * Comprehensive security layer that validates, sanitizes, and filters user inputs.
 * Works across projects with optional DOMPurify and config.
 *
 * USAGE:
 * ```typescript
 * import { createFirewall, sanitizeHtml } from '@creadev.org/security/firewall';
 *
 * // Create with optional config
 * const firewall = createFirewall({
 *   logLevel: 'warn',
 *   threatAction: 'block',
 *   dompurify: typeof import('dompurify').default,
 * });
 *
 * // Process HTML input
 * const result = firewall.process(userHtml, { type: 'html' });
 * if (!result.safe) {
 *   console.error('Blocked:', result.threats);
 * }
 * const clean = result.sanitized;
 * ```
 *
 * ============================================================================
 */
/** Severity levels for detected threats */
export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
/** Categories of detected threats */
export type ThreatCategory = 'xss' | 'sql_injection' | 'command_injection' | 'path_traversal' | 'prototype_pollution' | 'template_injection' | 'header_injection' | 'unicode_attack' | 'encoding_attack' | 'null_byte' | 'overflow' | 'malformed' | 'rate_limit' | 'suspicious';
/** Detected threat information */
export interface Threat {
    category: ThreatCategory;
    level: ThreatLevel;
    pattern: string;
    description: string;
    matched?: string;
}
/** Custom pattern for threat detection */
export interface CustomPattern {
    id: string;
    pattern: RegExp;
    category: ThreatCategory;
    level: ThreatLevel;
    description: string;
}
/** Input type being processed */
export type InputType = 'text' | 'html' | 'json' | 'url' | 'filename' | 'header' | 'email' | 'number';
/** Configuration for firewall */
export interface FirewallConfig {
    /** Enable threat detection (default: true) */
    enabled?: boolean;
    /** Logging level (default: 'warn') */
    logLevel?: 'debug' | 'info' | 'warn' | 'error';
    /** Action when threat detected (default: 'block') */
    threatAction?: 'log' | 'block' | 'sanitize';
    /** Minimum threat level to act on (default: 'low') */
    minThreatLevel?: ThreatLevel;
    /** Max input length in chars (default: 50000) */
    maxInputLength?: number;
    /** Processing area for custom patterns */
    area?: string;
    /** Custom threat patterns to add */
    customPatterns?: CustomPattern[];
    /** Paths/inputs to whitelist (skip scanning) */
    whitelist?: string[];
    /** DOMPurify instance (optional - for HTML sanitization) */
    dompurify?: {
        sanitize: (html: string, config?: object) => string;
    };
    /** DOMPurify config */
    dompurifyConfig?: object;
}
/** Result of processing input */
export interface FirewallResult {
    /** Whether input passed without critical threats */
    safe: boolean;
    /** Original input (before processing) */
    original: string;
    /** Sanitized/cleaned input */
    sanitized: string;
    /** All detected threats */
    threats: Threat[];
    /** Whether the firewall is enabled */
    firewallEnabled: boolean;
    /** Whether the input was whitelisted */
    whitelisted: boolean;
    /** Action taken */
    action: 'allowed' | 'blocked' | 'sanitized' | 'log';
    /** Processing metadata */
    meta: {
        processedAt: number;
        inputLength: number;
        outputLength: number;
        truncated: boolean;
        area?: string;
    };
}
/** Sanitize text input - remove control chars */
export declare function sanitizeText(input: string): string;
/** Sanitize HTML - uses DOMPurify if provided */
export declare function sanitizeHtml(input: string, dompurify?: {
    sanitize: (html: string, config?: object) => string;
}, config?: object): string;
/** Sanitize URL - encode dangerous protocols */
export declare function sanitizeUrl(input: string): string;
/** Sanitize filename - strip dangerous chars */
export declare function sanitizeFilename(input: string): string;
/** Sanitize JSON string */
export declare function sanitizeJson(input: string): string;
/** Sanitize generic input based on type */
export declare function sanitize(input: string, type: InputType, dompurify?: {
    sanitize: (html: string, config?: object) => string;
}, config?: object): string;
export interface FirewallInstance {
    process(input: string, options?: {
        type?: InputType;
    }): FirewallResult;
    isSafe(input: string): boolean;
    addPattern?(pattern: CustomPattern): void;
}
/** Create a firewall instance with optional config */
export declare function createFirewall(config?: FirewallConfig): FirewallInstance;
/** Secure validators - ready-to-use validation helpers */
export declare const secureValidators: {
    /** Validate and sanitize email */
    readonly email: (input: string) => {
        valid: boolean;
        value: string;
    };
    /** Validate and sanitize URL */
    readonly url: (input: string) => {
        valid: boolean;
        value: string;
    };
    /** Validate and sanitize filename */
    readonly filename: (input: string) => {
        valid: boolean;
        value: string;
    };
    /** Validate UUID format */
    readonly uuid: (input: string) => {
        valid: boolean;
        value: string;
    };
    /** Validate positive integer */
    readonly positiveInt: (input: string) => {
        valid: boolean;
        value: number;
    };
};
/** Default firewall with sensible defaults - ready to use out of the box */
export declare const firewall: FirewallInstance & {
    process(input: unknown, options?: {
        type?: InputType;
        maxLength?: number;
        area?: string;
    }): FirewallResult;
    isSafe(input: string): boolean;
};
/**
 * Runtime config accessors for the firewall.
 * Use setConfig() to customize behavior.
 */
export declare const securityConfig: {
    /** Check if firewall is enabled */
    readonly isEnabled: () => boolean;
    /** Get current log level */
    readonly getLogLevel: () => "debug" | "info" | "warn" | "error";
    /** Get current threat action */
    readonly getThreatAction: () => "log" | "block" | "sanitize";
    /** Get minimum threat level that triggers action */
    readonly getMinimumThreatLevel: () => ThreatLevel;
    /** Get max input length */
    readonly getMaxInputLength: () => number;
    /** Get number of custom patterns configured */
    readonly getCustomPatternCount: () => number;
    /** Get whitelist entries count */
    readonly getWhitelistCount: () => number;
    /** Get full security status */
    readonly getStatus: () => {
        enabled: boolean;
        logLevel: string;
        threatAction: string;
        minThreatLevel: string;
        maxInputLength: number;
        customPatterns: number;
        whitelist: number;
    };
    /** Set configuration */
    readonly setConfig: (config: FirewallConfig) => void;
    /** Reset to defaults */
    readonly resetConfig: () => void;
};
/** Active areas for processing - enables selective firewall per input zone */
export declare const SECURITY_ACTIVE_AREAS: {
    readonly input: true;
    readonly comment: true;
    readonly title: true;
    readonly content: true;
    readonly url: true;
    readonly json: true;
    readonly header: true;
};
/** Check if an area is active */
export declare function isAreaActive(area: string): boolean;
