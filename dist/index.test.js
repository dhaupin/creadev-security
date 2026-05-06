import { describe, it, expect, beforeEach } from 'vitest';
import { RateLimiter, sanitizePath, sanitizeRepoName, createWaf } from '../src/index';
describe('RateLimiter', () => {
    let limiter;
    beforeEach(() => {
        limiter = new RateLimiter({ maxRequests: 3, windowMs: 1000, cleanupIntervalMs: 5000 });
    });
    it('allows requests under limit', () => {
        const result = limiter.check('user-1');
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(2);
    });
    it('tracks remaining requests', () => {
        limiter.check('user-1');
        limiter.check('user-1');
        const result = limiter.check('user-1');
        expect(result.remaining).toBe(0);
    });
    it('blocks when limit exceeded', () => {
        limiter.check('user-1');
        limiter.check('user-1');
        limiter.check('user-1');
        const result = limiter.check('user-1');
        expect(result.allowed).toBe(false);
        expect(result.retryAfter).toBeGreaterThan(0);
    });
    it('tracks per key separately', () => {
        limiter.check('user-1');
        limiter.check('user-1');
        limiter.check('user-1');
        const r1 = limiter.check('user-1');
        const r2 = limiter.check('user-2');
        expect(r1.allowed).toBe(false);
        expect(r2.allowed).toBe(true);
    });
    it('resets after window expiry', async () => {
        const l = new RateLimiter({ maxRequests: 1, windowMs: 50 });
        l.check('user-1');
        expect(l.check('user-1').allowed).toBe(false);
        await new Promise(r => setTimeout(r, 60));
        expect(l.check('user-1').allowed).toBe(true);
    });
    it('reset removes limit for key', () => {
        limiter.check('user-1');
        limiter.check('user-1');
        limiter.check('user-1');
        limiter.reset('user-1');
        expect(limiter.check('user-1').allowed).toBe(true);
    });
    it('returns correct remaining count', () => {
        limiter.check('user-1');
        expect(limiter.remaining('user-1')).toBe(2);
    });
});
describe('sanitizePath', () => {
    it('allows safe relative paths', () => {
        expect(sanitizePath('my-project')).toBe('my-project');
        expect(sanitizePath('src/components/Button.tsx')).toBe('src/components/Button.tsx');
        expect(sanitizePath('./config/app.json')).toBe('./config/app.json');
    });
    it('blocks parent traversal', () => {
        expect(sanitizePath('../etc/passwd')).toBe(null);
        expect(sanitizePath('../../.env')).toBe(null);
        expect(sanitizePath('foo/../../../bar')).toBe(null);
    });
    it('blocks absolute paths', () => {
        expect(sanitizePath('/etc/passwd')).toBe(null);
        expect(sanitizePath('/home/user')).toBe(null);
    });
    it('blocks Windows drives', () => {
        expect(sanitizePath('C:\\Windows')).toBe(null);
        expect(sanitizePath('D:/data')).toBe(null);
    });
    it('blocks invalid characters', () => {
        expect(sanitizePath('foo|bar')).toBe(null);
        expect(sanitizePath('foo$bar')).toBe(null);
        expect(sanitizePath('foo\nbar')).toBe(null);
    });
    it('returns null for empty/null input', () => {
        expect(sanitizePath('')).toBe(null);
        expect(sanitizePath(null)).toBe(null);
        expect(sanitizePath(undefined)).toBe(null);
    });
});
describe('sanitizeRepoName', () => {
    it('allows valid repo names', () => {
        expect(sanitizeRepoName('my-repo')).toBe('my-repo');
        expect(sanitizeRepoName('threadforge')).toBe('threadforge');
        expect(sanitizeRepoName('prefix-suffix')).toBe('prefix-suffix');
        expect(sanitizeRepoName('prefix_suffix')).toBe('prefix_suffix');
        expect(sanitizeRepoName('repo.name')).toBe('repo.name');
    });
    it('blocks invalid names', () => {
        expect(sanitizeRepoName('my repo')).toBe(null);
        expect(sanitizeRepoName('my/repo')).toBe(null);
        expect(sanitizeRepoName('../repo')).toBe(null);
    });
    it('blocks too long names', () => {
        expect(sanitizeRepoName('a'.repeat(101))).toBe(null);
        expect(sanitizeRepoName('a'.repeat(100))).toBe('a'.repeat(100));
    });
});
describe('createWaf', () => {
    it('allows safe requests', () => {
        const waf = createWaf();
        const result = waf.checkQuery('search=test');
        expect(result.allowed).toBe(true);
    });
    it('blocks XSS patterns', () => {
        const waf = createWaf();
        expect(waf.checkQuery('<script>alert(1)</script>').allowed).toBe(false);
        expect(waf.checkQuery('javascript:alert(1)').allowed).toBe(false);
    });
    it('blocks SQL patterns', () => {
        const waf = createWaf();
        expect(waf.checkQuery('id=1 UNION SELECT').allowed).toBe(false);
        expect(waf.checkQuery('id=1; DROP TABLE').allowed).toBe(false);
    });
    it('checks body size', () => {
        const waf = createWaf({ maxBodySize: 100 });
        expect(waf.checkBodySize({ 'content-length': '50' })).toBe(true);
        expect(waf.checkBodySize({ 'content-length': '200' })).toBe(false);
    });
});
