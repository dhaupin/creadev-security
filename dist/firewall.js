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
// ============================================================================
// THREAT PATTERNS
// ============================================================================
const THREAT_LEVELS = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
};
/** Default threat detection patterns */
const DEFAULT_PATTERNS = [
    // XSS patterns
    { pattern: /<script[^>]*>/i, category: 'xss', level: 'critical', description: 'Script tag detected' },
    { pattern: /javascript:/i, category: 'xss', level: 'critical', description: 'JavaScript protocol' },
    { pattern: /on\w+\s*=/i, category: 'xss', level: 'critical', description: 'Inline event handler' },
    { pattern: /<iframe/i, category: 'xss', level: 'high', description: 'Iframe tag detected' },
    { pattern: /<object/i, category: 'xss', level: 'high', description: 'Object tag detected' },
    { pattern: /<embed/i, category: 'xss', level: 'high', description: 'Embed tag detected' },
    { pattern: /expression\s*\(/i, category: 'xss', level: 'critical', description: 'CSS expression' },
    { pattern: /eval\s*\(/i, category: 'xss', level: 'critical', description: 'Eval function call' },
    { pattern: /alert\s*\(/i, category: 'xss', level: 'medium', description: 'Alert function call' },
    // SQL Injection
    { pattern: /\bunion\s+select\b/i, category: 'sql_injection', level: 'critical', description: 'Union select attack' },
    { pattern: /\bselect\s+from\b/i, category: 'sql_injection', level: 'medium', description: 'Select from attack' },
    { pattern: /\bdrop\s+table\b/i, category: 'sql_injection', level: 'critical', description: 'Drop table attack' },
    { pattern: /\bdrop\s+database\b/i, category: 'sql_injection', level: 'critical', description: 'Drop database attack' },
    { pattern: /\binsert\s+into\b/i, category: 'sql_injection', level: 'medium', description: 'Insert into attack' },
    { pattern: /\bupdate\s+\w+\s+set\b/i, category: 'sql_injection', level: 'critical', description: 'Update set attack' },
    { pattern: /--\s*$/m, category: 'sql_injection', level: 'high', description: 'SQL comment' },
    { pattern: /\/\*.*\*\//i, category: 'sql_injection', level: 'high', description: 'Block SQL comment' },
    { pattern: /xp_/i, category: 'sql_injection', level: 'high', description: 'Extended stored procedure' },
    // Command Injection
    { pattern: /\|\s*grep/i, category: 'command_injection', level: 'high', description: 'Pipe to grep' },
    { pattern: /\|\s*cat/i, category: 'command_injection', level: 'high', description: 'Pipe to cat' },
    { pattern: /;\s*rm\s+-rf/i, category: 'command_injection', level: 'critical', description: 'Recursive delete' },
    { pattern: /&\s*curl\s+/i, category: 'command_injection', level: 'high', description: 'Curl command' },
    { pattern: /`[^`]+`/i, category: 'command_injection', level: 'high', description: 'Command substitution' },
    { pattern: /\$\([^)]+\)/i, category: 'command_injection', level: 'high', description: 'Command substitution' },
    { pattern: /\$\{[^}]+\}/i, category: 'command_injection', level: 'high', description: 'Variable expansion' },
    // Path Traversal
    { pattern: /\.\.[\\/]/i, category: 'path_traversal', level: 'critical', description: 'Directory traversal' },
    { pattern: /%2e%2e/i, category: 'path_traversal', level: 'critical', description: 'Encoded traversal' },
    { pattern: /\/etc\/passwd/i, category: 'path_traversal', level: 'critical', description: 'Password file access' },
    { pattern: /\/etc\/shadow/i, category: 'path_traversal', level: 'critical', description: 'Shadow file access' },
    { pattern: /C:\\/i, category: 'path_traversal', level: 'high', description: 'Windows path' },
    { pattern: /^[a-zA-Z]:\\/i, category: 'path_traversal', level: 'high', description: 'Absolute Windows path' },
    // Prototype Pollution
    { pattern: /__proto__/i, category: 'prototype_pollution', level: 'critical', description: 'Prototype pollution' },
    { pattern: /constructor\.prototype/i, category: 'prototype_pollution', level: 'critical', description: 'Constructor access' },
    { pattern: /__defineGetter__/i, category: 'prototype_pollution', level: 'high', description: 'Prototype method access' },
    // Template Injection
    { pattern: /\{\{/, category: 'template_injection', level: 'high', description: 'Template expression' },
    { pattern: /\}\}/, category: 'template_injection', level: 'high', description: 'Template expression' },
    { pattern: /\{\{\{/, category: 'template_injection', level: 'high', description: 'Triple brace' },
    // Header Injection
    { pattern: /\r\n/i, category: 'header_injection', level: 'critical', description: 'CRLF injection' },
    { pattern: /\n\r/, category: 'header_injection', level: 'critical', description: 'CRLF injection' },
    // Unicode Attacks
    { pattern: /[\u200b-\u200d\ufeff]/i, category: 'unicode_attack', level: 'medium', description: 'Zero-width char' },
    { pattern: /%u/i, category: 'encoding_attack', level: 'medium', description: 'Unicode encoding' },
    // Null Byte
    { pattern: /\x00/i, category: 'null_byte', level: 'high', description: 'Null byte injection' },
    { pattern: /%00/i, category: 'null_byte', level: 'high', description: 'Encoded null byte' },
    // Overflow
    { pattern: /.{10000,}/i, category: 'overflow', level: 'medium', description: 'Excessive length' },
    // Malformed
    { pattern: /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/i, category: 'malformed', level: 'low', description: 'Control characters' },
];
// ============================================================================
// THREAT DETECTION
// ============================================================================
/** Check input for threats */
function detectThreats(input, patterns) {
    const threats = [];
    for (const { pattern, category, level, description } of patterns) {
        const match = input.match(pattern);
        if (match) {
            threats.push({
                category,
                level,
                pattern: pattern.source,
                description,
                matched: match[0]?.substring(0, 50),
            });
        }
    }
    return threats;
}
// ============================================================================
// SANITIZATION
// ============================================================================
/** Sanitize text input - remove control chars */
export function sanitizeText(input) {
    return input
        .normalize('NFC')
        .replace(/[\u200b-\u200d\ufeff\u00AD]/g, '')
        .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
}
/** Sanitize HTML - uses DOMPurify if provided */
export function sanitizeHtml(input, dompurify, config) {
    if (dompurify) {
        return dompurify.sanitize(input, { ...config, RETURN_TRUSTED_TYPE: false });
    }
    // Fallback: basic tag stripping if no DOMPurify
    return input
        .replace(/<script\b[^<]*(?:<(?:\/script)|>)/gi, '')
        .replace(/<iframe\b[^<]*(?:<(?:\/iframe)|>)/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '');
}
/** Sanitize URL - encode dangerous protocols */
export function sanitizeUrl(input) {
    try {
        const url = new URL(input);
        if (url.protocol === 'javascript:' || url.protocol === 'data:') {
            return encodeURI(input);
        }
        return input;
    }
    catch {
        // Not a URL, encode it
        return encodeURI(input);
    }
}
/** Sanitize filename - strip dangerous chars */
export function sanitizeFilename(input) {
    return input
        .replace(/[\\/]/g, '/')
        .replace(/\.\.+/g, '.')
        .replace(/[\x00-\x1f\x7f]/g, '')
        .slice(0, 255);
}
/** Sanitize JSON string */
export function sanitizeJson(input) {
    try {
        const parsed = JSON.parse(input);
        return JSON.stringify(parsed);
    }
    catch {
        return sanitizeText(input);
    }
}
/** Sanitize generic input based on type */
export function sanitize(input, type, dompurify, config) {
    switch (type) {
        case 'html':
            return sanitizeHtml(input, dompurify, config);
        case 'url':
            return sanitizeUrl(input);
        case 'filename':
            return sanitizeFilename(input);
        case 'json':
            return sanitizeJson(input);
        case 'header':
        case 'text':
        default:
            return sanitizeText(input);
    }
}
/** Create a firewall instance with optional config */
export function createFirewall(config = {}) {
    const { enabled = true, logLevel = 'warn', threatAction = 'block', minThreatLevel = 'low', maxInputLength = 50000, customPatterns = [], whitelist = [], dompurify, dompurifyConfig, } = config;
    // Combine default + custom patterns
    const allPatterns = [...DEFAULT_PATTERNS, ...customPatterns.map((p) => ({
            pattern: p.pattern,
            category: p.category,
            level: p.level,
            description: p.description,
        }))];
    // Helper to log
    const log = (level, msg) => {
        if (!enabled)
            return;
        const levelNum = THREAT_LEVELS[level];
        const minNum = THREAT_LEVELS[minThreatLevel];
        if (levelNum >= minNum) {
            const logFn = level === 'critical' || level === 'high' ? console.error : logLevel === 'debug' ? console.debug : console.warn;
            logFn(`[firewall] ${level}: ${msg}`);
        }
    };
    const instance = {
        /** Process input and return result */
        process(input, options) {
            const { type = 'text' } = options ?? {};
            const startTime = Date.now();
            const rawInput = input;
            // Check whitelist
            if (whitelist.some((w) => rawInput.includes(w))) {
                return { safe: true, original: rawInput, sanitized: rawInput, threats: [], firewallEnabled: true, whitelisted: true, action: 'allowed', meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: rawInput.length, truncated: false } };
            }
            // Check length
            if (rawInput.length > maxInputLength) {
                log('medium', `Input exceeds max length: ${rawInput.length} > ${maxInputLength}`);
                return {
                    safe: false,
                    original: rawInput,
                    sanitized: rawInput.slice(0, maxInputLength),
                    threats: [{ category: 'overflow', level: 'medium', pattern: '.{10000,}', description: 'Excessive length' }],
                    firewallEnabled: true,
                    whitelisted: false,
                    action: 'blocked',
                    meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: maxInputLength, truncated: true },
                };
            }
            // Detect threats
            const threats = detectThreats(rawInput, allPatterns);
            // Determine if critical
            const hasCritical = threats.some((t) => t.level === 'critical' || t.level === 'high');
            const hasMedium = threats.some((t) => t.level === 'medium');
            if (hasCritical || hasMedium) {
                for (const threat of threats) {
                    log(threat.level, `${threat.category}: ${threat.description}`);
                }
            }
            // No threats - allow
            if (threats.length === 0) {
                return { safe: true, original: rawInput, sanitized: rawInput, threats: [], firewallEnabled: true, whitelisted: false, action: 'allowed', meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: rawInput.length, truncated: false } };
            }
            // Action based on config
            if (threatAction === 'block' || (threatAction === 'sanitize' && hasCritical)) {
                return { safe: false, original: rawInput, sanitized: rawInput, threats, firewallEnabled: true, whitelisted: false, action: 'blocked', meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: rawInput.length, truncated: false } };
            }
            // Log only - allow but log threats
            if (threatAction === 'log') {
                const logAction = hasCritical || threats.length > 0 ? 'log' : 'allowed';
                return {
                    safe: hasCritical ? false : true,
                    original: rawInput,
                    sanitized: rawInput,
                    threats,
                    firewallEnabled: true,
                    whitelisted: false,
                    action: logAction,
                    meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: rawInput.length, truncated: false },
                };
            }
            // Sanitize or allow
            const sanitized = sanitize(rawInput, type, dompurify, dompurifyConfig);
            return {
                safe: !hasCritical,
                original: rawInput,
                sanitized,
                threats,
                firewallEnabled: true,
                whitelisted: false,
                action: threatAction === 'sanitize' ? 'sanitized' : 'allowed',
                meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: sanitized.length, truncated: false },
            };
        },
        /** Quick check if input is safe */
        isSafe(input) {
            const result = instance.process(input, { type: 'text' });
            return result.safe;
        },
        /** Add custom pattern at runtime */
        addPattern(pattern) {
            allPatterns.push({
                pattern: pattern.pattern,
                category: pattern.category,
                level: pattern.level,
                description: pattern.description,
            });
        },
    };
    return instance;
}
// ============================================================================
// SECURE VALIDATORS
// ============================================================================
/** Secure validators - ready-to-use validation helpers */
export const secureValidators = {
    /** Validate and sanitize email */
    email(input) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const sanitized = sanitizeText(input).slice(0, 254);
        const valid = emailRegex.test(sanitized);
        return { valid, value: sanitized };
    },
    /** Validate and sanitize URL */
    url(input) {
        const sanitized = sanitizeText(input).slice(0, 2048);
        try {
            const url = new URL(sanitized);
            return { valid: sanitized !== '' && url.protocol !== 'javascript:', value: sanitized };
        }
        catch {
            return { valid: false, value: '' };
        }
    },
    /** Validate and sanitize filename */
    filename(input) {
        const sanitized = sanitizeFilename(input).slice(0, 255);
        const valid = sanitized.length > 0 && !sanitized.includes('/');
        return { valid, value: sanitized };
    },
    /** Validate UUID format */
    uuid(input) {
        const sanitized = sanitizeText(input).slice(0, 36);
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        const valid = uuidRegex.test(sanitized);
        return { valid, value: sanitized };
    },
    /** Validate positive integer */
    positiveInt(input) {
        const sanitized = sanitizeText(input).slice(0, 20);
        const num = parseInt(sanitized, 10);
        const valid = Number.isInteger(num) && num > 0;
        return { valid, value: valid ? num : 0 };
    },
};
// ============================================================================
// DEFAULT FIREWALL INSTANCE
// ============================================================================
/** Default firewall with sensible defaults - ready to use out of the box */
export const firewall = {
    /**
     * Process input through the security firewall.
     * Detects threats, sanitizes content, and validates format.
     */
    process(input, options = {}) {
        const { type = 'text', maxLength = 50000, area } = options;
        const rawInput = typeof input === 'string' ? input : String(input ?? '');
        const startTime = Date.now();
        const truncated = rawInput.length > maxLength;
        // Check if disabled (via config if set)
        const config = getFirewallConfig();
        if (!config.enabled) {
            return {
                safe: true,
                original: rawInput,
                sanitized: rawInput,
                threats: [],
                firewallEnabled: false,
                whitelisted: false,
                action: 'allowed',
                meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: rawInput.length, truncated, area },
            };
        }
        // Check whitelist
        const whitelisted = config.whitelist?.some((w) => rawInput.includes(w)) ?? false;
        if (whitelisted) {
            return {
                safe: true,
                original: rawInput,
                sanitized: rawInput,
                threats: [],
                firewallEnabled: true,
                whitelisted: true,
                action: 'allowed',
                meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: rawInput.length, truncated, area },
            };
        }
        // Check length
        if (truncated) {
            return {
                safe: false,
                original: rawInput,
                sanitized: rawInput.slice(0, maxLength),
                threats: [{ category: 'overflow', level: 'medium', pattern: '.{50000,}', description: 'Excessive length', matched: rawInput.slice(maxLength) }],
                firewallEnabled: true,
                whitelisted: false,
                action: 'blocked',
                meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: maxLength, truncated: true, area },
            };
        }
        // Detect threats
        const threats = detectThreats(rawInput, DEFAULT_PATTERNS);
        const hasCritical = threats.some((t) => t.level === 'critical' || t.level === 'high');
        // No threats - allow
        if (threats.length === 0) {
            return {
                safe: true,
                original: rawInput,
                sanitized: rawInput,
                threats: [],
                firewallEnabled: true,
                whitelisted: false,
                action: 'allowed',
                meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: rawInput.length, truncated: false, area },
            };
        }
        // Action based on config
        if (config.threatAction === 'block' || config.threatAction === 'sanitize') {
            return {
                safe: false,
                original: rawInput,
                sanitized: rawInput,
                threats,
                firewallEnabled: true,
                whitelisted: false,
                action: 'blocked',
                meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: rawInput.length, truncated: false, area },
            };
        }
        // Log only - sanitize
        const sanitized = sanitize(rawInput, type);
        return {
            safe: !hasCritical,
            original: rawInput,
            sanitized,
            threats,
            firewallEnabled: true,
            whitelisted: false,
            action: 'sanitized',
            meta: { processedAt: startTime, inputLength: rawInput.length, outputLength: sanitized.length, truncated: false, area },
        };
    },
    /** Quick check if input is safe */
    isSafe(input) {
        return this.process(input).safe;
    },
};
// Internal config storage
let _config;
function getFirewallConfig() {
    if (!_config) {
        return {
            enabled: true,
            logLevel: 'warn',
            threatAction: 'block',
            minThreatLevel: 'low',
            maxInputLength: 50000,
            customPatterns: [],
            whitelist: [],
        };
    }
    return {
        enabled: _config.enabled ?? true,
        logLevel: _config.logLevel ?? 'warn',
        threatAction: _config.threatAction ?? 'block',
        minThreatLevel: _config.minThreatLevel ?? 'low',
        maxInputLength: _config.maxInputLength ?? 50000,
        area: _config.area,
        customPatterns: _config.customPatterns ?? [],
        whitelist: _config.whitelist ?? [],
        dompurify: _config.dompurify,
        dompurifyConfig: _config.dompurifyConfig,
    };
}
// ============================================================================
// SECURITY CONFIG
// ============================================================================
/**
 * Runtime config accessors for the firewall.
 * Use setConfig() to customize behavior.
 */
export const securityConfig = {
    /** Check if firewall is enabled */
    isEnabled() {
        return getFirewallConfig().enabled;
    },
    /** Get current log level */
    getLogLevel() {
        return getFirewallConfig().logLevel;
    },
    /** Get current threat action */
    getThreatAction() {
        return getFirewallConfig().threatAction;
    },
    /** Get minimum threat level that triggers action */
    getMinimumThreatLevel() {
        return getFirewallConfig().minThreatLevel;
    },
    /** Get max input length */
    getMaxInputLength() {
        return getFirewallConfig().maxInputLength;
    },
    /** Get number of custom patterns configured */
    getCustomPatternCount() {
        return getFirewallConfig().customPatterns.length;
    },
    /** Get whitelist entries count */
    getWhitelistCount() {
        return getFirewallConfig().whitelist.length;
    },
    /** Get full security status */
    getStatus() {
        const cfg = getFirewallConfig();
        return {
            enabled: cfg.enabled,
            logLevel: cfg.logLevel,
            threatAction: cfg.threatAction,
            minThreatLevel: cfg.minThreatLevel,
            maxInputLength: cfg.maxInputLength,
            customPatterns: cfg.customPatterns.length,
            whitelist: cfg.whitelist.length,
        };
    },
    /** Set configuration */
    setConfig(config) {
        _config = config;
    },
    /** Reset to defaults */
    resetConfig() {
        _config = undefined;
    },
};
// ============================================================================
// AREA-BASED FILTERING
// ============================================================================
/** Active areas for processing - enables selective firewall per input zone */
export const SECURITY_ACTIVE_AREAS = {
    input: true,
    comment: true,
    title: true,
    content: true,
    url: true,
    json: true,
    header: true,
};
/** Check if an area is active */
export function isAreaActive(area) {
    return SECURITY_ACTIVE_AREAS[area] ?? true;
}
