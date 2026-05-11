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
export declare function validateUUID(id: unknown): id is string;
/**
 * Validates multiple UUIDs at once
 */
export declare function validateUUIDs(...ids: unknown[]): boolean;
/**
 * Validates Git branch names according to git-check-ref-format rules
 * Rules: no start with . or -, no .., no control chars, no .lock suffix, max 255
 */
export declare function validateBranchName(branch: unknown): branch is string;
/**
 * Sanitizes a branch name with a safe default if invalid
 */
export declare function safeBranchName(branch: unknown, defaultBranch?: string): string;
/**
 * Validates file paths to prevent path traversal
 * Allows dotfiles, framework-specific chars (Cloudflare [[path]], Next.js [slug].tsx, etc.)
 */
export declare function validateFilePath(filePath: unknown): filePath is string;
/**
 * Validates an array of file paths
 */
export declare function validateFilePaths(paths: unknown): paths is string[];
export declare function validateSHA(sha: unknown): sha is string;
export declare function validateShortSHA(sha: unknown): sha is string;
/**
 * Validates GitHub repository full names (owner/repo format)
 */
export declare function validateRepoFullName(fullName: unknown): fullName is string;
/**
 * Safely splits a repo full name into owner/repo
 */
export declare function parseRepoFullName(fullName: unknown): {
    owner: string;
    repo: string;
} | null;
/**
 * Validates commit message content - allows printable chars, blocks control chars
 */
export declare function validateCommitMessage(message: unknown): message is string;
