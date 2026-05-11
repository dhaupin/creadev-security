/**
 * ============================================================================
 * Input Validation - Git/Development Compatible
 * ============================================================================
 *
 * PURPOSE:
 * Generic input validation utilities for git, GitHub, and development workflows.
 * Prevents injection attacks, path traversal, and malformed inputs.
 *
 * USAGE:
 * ```typescript
 * import { validateUUID, validateBranchName, validateFilePath } from '@creadev.org/security/validation';
 *
 * if (!validateUUID(repoId)) {
 *   throw new Error('Invalid repository ID');
 * }
 * ```
 *
 * ============================================================================
 */
// ============================================================================
// UUID VALIDATION
// ============================================================================
/**
 * Validates that a string is a properly formatted UUID v4
 * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (8-4-4-4-12 hex chars)
 */
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function validateUUID(id) {
    return typeof id === 'string' && UUID_REGEX.test(id);
}
/**
 * Validates multiple UUIDs at once
 */
export function validateUUIDs(...ids) {
    return ids.every(validateUUID);
}
// ============================================================================
// BRANCH NAME VALIDATION
// ============================================================================
const SAFE_BRANCH_REGEX = /^[a-zA-Z0-9][\w\-./]*$/;
const INVALID_BRANCH_PATTERNS = [
    /\.\./, // Path traversal
    /^-/, // Starts with dash
    /\/\//, // Double slashes
    /\.lock$/, // Ends with .lock
    /@\{/, // Git reflog syntax
    /[\x00-\x1f\x7f]/, // Control characters
    /[\s~^:?*\[\]\\]/, // Special characters
];
/**
 * Validates Git branch names according to git-check-ref-format rules
 * Rules: no start with . or -, no .., no control chars, no .lock suffix, max 255
 */
export function validateBranchName(branch) {
    if (typeof branch !== 'string')
        return false;
    if (branch.length === 0 || branch.length > 255)
        return false;
    if (!SAFE_BRANCH_REGEX.test(branch))
        return false;
    return !INVALID_BRANCH_PATTERNS.some(pattern => pattern.test(branch));
}
/**
 * Sanitizes a branch name with a safe default if invalid
 */
export function safeBranchName(branch, defaultBranch = 'main') {
    return validateBranchName(branch) ? branch : defaultBranch;
}
// ============================================================================
// FILE PATH VALIDATION
// ============================================================================
const SAFE_PATH_REGEX = /^[^\x00-\x1f\x7f/\\][^\x00-\x1f\x7f\\]*$/;
const INVALID_PATH_PATTERNS = [
    /\.\./, // Path traversal
    /^\//, // Absolute paths
    /\/\//, // Double slashes
    /\x00/, // Null byte injection
    /[\x00-\x1f\x7f]/, // Control characters
];
/**
 * Validates file paths to prevent path traversal
 * Allows dotfiles, framework-specific chars (Cloudflare [[path]], Next.js [slug].tsx, etc.)
 */
export function validateFilePath(filePath) {
    if (typeof filePath !== 'string')
        return false;
    if (filePath.length === 0 || filePath.length > 1000)
        return false;
    if (!SAFE_PATH_REGEX.test(filePath))
        return false;
    return !INVALID_PATH_PATTERNS.some(pattern => pattern.test(filePath));
}
/**
 * Validates an array of file paths
 */
export function validateFilePaths(paths) {
    if (!Array.isArray(paths))
        return false;
    return paths.every(validateFilePath);
}
// ============================================================================
// GIT SHA VALIDATION
// ============================================================================
/**
 * Validates Git commit SHA format (40 hex characters)
 */
const SHA_REGEX = /^[0-9a-f]{40}$/i;
export function validateSHA(sha) {
    return typeof sha === 'string' && SHA_REGEX.test(sha);
}
/**
 * Validates short SHA (7+ hex characters)
 */
const SHORT_SHA_REGEX = /^[0-9a-f]{7,40}$/i;
export function validateShortSHA(sha) {
    return typeof sha === 'string' && SHORT_SHA_REGEX.test(sha);
}
// ============================================================================
// REPOSITORY NAME VALIDATION
// ============================================================================
const REPO_NAME_REGEX = /^[a-zA-Z0-9][\w.-]{0,99}$/;
/**
 * Validates GitHub repository full names (owner/repo format)
 */
export function validateRepoFullName(fullName) {
    if (typeof fullName !== 'string')
        return false;
    const parts = fullName.split('/');
    if (parts.length !== 2)
        return false;
    const [owner, repo] = parts;
    return REPO_NAME_REGEX.test(owner) && REPO_NAME_REGEX.test(repo);
}
/**
 * Safely splits a repo full name into owner/repo
 */
export function parseRepoFullName(fullName) {
    if (!validateRepoFullName(fullName))
        return null;
    const [owner, repo] = fullName.split('/');
    return { owner, repo };
}
// ============================================================================
// STRING SANITIZATION
// ============================================================================
/**
 * Validates commit message content - allows printable chars, blocks control chars
 */
export function validateCommitMessage(message) {
    if (typeof message !== 'string')
        return false;
    if (message.length === 0 || message.length > 5000)
        return false;
    // Block null bytes and most control characters (allow newlines, tabs)
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(message))
        return false;
    return true;
}
