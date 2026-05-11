# @creadev.org/security

> Security utilities shared between weisync, migrare, Threadforge, and other projects.

[![npm](https://img.shields.io/npm/v/@creadev.org/security)](https://www.npmjs.com/package/@creadev.org/security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Install

```bash
npm install @creadev.org/security
```

## Usage

### Rate Limiting

```typescript
import { RateLimiter } from '@creadev.org/security';

const limiter = new RateLimiter({ maxRequests: 30, windowMs: 60000 });

// Check if request is allowed
const result = limiter.check('user-id');
if (!result.allowed) {
  console.log(`Retry after ${result.retryAfter}ms`);
}
```

### Firewall (Input Validation)

```typescript
import { firewall, createFirewall } from '@creadev.org/security';

// Use default firewall instance
const result = firewall.process(userInput, { type: 'text' });
if (!result.safe) {
  console.log('Input blocked:', result.threats);
}

// Or create custom firewall
const custom = createFirewall({ 
  threatAction: 'log',
  logLevel: 'debug' 
});
const customResult = custom.process(userInput, { type: 'html' });
```

### Input Sanitization

```typescript
import { sanitizePath, sanitizeUrl, sanitizeFilename } from '@creadev.org/security';

sanitizePath('../../etc/passwd');  // null (blocked)
sanitizeUrl('javascript:alert(1)');    // null (blocked)
sanitizeFilename('my file.txt');       // 'my-file.txt' (safe)
```

### Validators

```typescript
import { secureValidators, securityConfig } from '@creadev.org/security';

// Check format
secureValidators.email('test@example.com'); // { valid: true }
secureValidators.uuid('550e8400-…');         // { valid: true }
secureValidators.positiveInt('42');           // { valid: true }

// Get security config
securityConfig.isEnabled();    // true
securityConfig.getLogLevel();  // 'warn'
securityConfig.getStatus();    // { enabled, logLevel, … }
```

## API

### Rate Limiter

| Method | Description |
|-------|-------------|
| `new RateLimiter(opts)` | Create limiter with `maxRequests`, `windowMs`, `cleanupIntervalMs` |
| `limiter.check(key)` | Check if request allowed, returns `{ allowed, remaining, retryAfter }` |
| `limiter.reset(key)` | Reset limiter for key |
| `limiter.resetAll()` | Reset all limiters |

### Firewall

| Method | Description |
|-------|-------------|
| `firewall.process(input, opts)` | Process input, returns `FirewallResult` |
| `createFirewall(config?)` | Create custom firewall instance |
| `isAreaActive(area)` | Check if area is active |

### FirewallResult

```typescript
interface FirewallResult {
  safe: boolean;
  original: string;
  sanitized: string;
  threats: Threat[];
  firewallEnabled: boolean;
  whitelisted: boolean;
  action: 'allowed' | 'blocked' | 'sanitized' | 'log';
  meta: { processedAt, inputLength, outputLength, truncated, area? };
}
```

### Validators

| Function | Description |
|----------|-------------|
| `secureValidators.email(input)` | Validate email format |
| `secureValidators.url(input)` | Validate URL format |
| `secureValidators.uuid(input)` | Validate UUID format |
| `secureValidators.filename(input)` | Validate filename (no path traversal) |
| `secureValidators.positiveInt(input)` | Validate positive integer |

## Types

```typescript
import type { 
  Threat, 
  ThreatLevel, 
  ThreatCategory,
  InputType,
  FirewallConfig,
  FirewallResult,
} from '@creadev.org/security';
```

## License

MIT
