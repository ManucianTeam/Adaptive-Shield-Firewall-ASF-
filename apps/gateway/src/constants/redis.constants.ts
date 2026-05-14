// apps/gateway/src/redis/redis.constants.ts

// ============================================================================
// ASF Redis Constants
// ============================================================================
//
// Purpose:
//   Centralized Redis-related constants for the
//   Adaptive Shield Firewall (ASF) Gateway.
//
// Responsibilities:
//   - Dependency injection tokens
//   - Redis key namespaces
//   - Cache prefixes
//   - Pub/Sub channels
//   - Distributed lock identifiers
//   - TTL defaults
//
// Architecture Notes:
//   All Redis keys are namespaced using the `asf:` prefix
//   to prevent collisions across environments/services.
//
// Naming Convention:
//   asf:<domain>:<resource>:<identifier>
//
// Example:
//   asf:session:user:123
//
// ============================================================================

// ============================================================================
// Dependency Injection Tokens
// ============================================================================

export const REDIS_CLIENT = 'REDIS_CLIENT';

export const REDIS_SUBSCRIBER = 'REDIS_SUBSCRIBER';

export const REDIS_PUBLISHER = 'REDIS_PUBLISHER';

// ============================================================================
// Root Namespace
// ============================================================================

export const REDIS_NAMESPACE = 'asf';

// ============================================================================
// Session Keys
// ============================================================================

export const REDIS_SESSION_PREFIX = 'asf:session:';

export const REDIS_REFRESH_TOKEN_PREFIX = 'asf:refresh-token:';

// ============================================================================
// Cache Keys
// ============================================================================

export const REDIS_CACHE_PREFIX = 'asf:cache:';

export const REDIS_RESPONSE_CACHE_PREFIX = 'asf:response-cache:';

// ============================================================================
// Authentication Keys
// ============================================================================

export const REDIS_AUTH_PREFIX = 'asf:auth:';

export const REDIS_LOGIN_ATTEMPT_PREFIX = 'asf:login-attempt:';

export const REDIS_BRUTE_FORCE_PREFIX = 'asf:bruteforce:';

// ============================================================================
// Rate Limiting Keys
// ============================================================================

export const REDIS_RATE_LIMIT_PREFIX = 'asf:ratelimit:';

export const REDIS_THROTTLE_PREFIX = 'asf:throttle:';

// ============================================================================
// Security Keys
// ============================================================================

export const REDIS_SECURITY_PREFIX = 'asf:security:';

export const REDIS_IP_REPUTATION_PREFIX = 'asf:ip-reputation:';

export const REDIS_FINGERPRINT_PREFIX = 'asf:fingerprint:';

export const REDIS_ANOMALY_PREFIX = 'asf:anomaly:';

// ============================================================================
// Distributed Locks
// ============================================================================

export const REDIS_LOCK_PREFIX = 'asf:lock:';

export const REDIS_DISTRIBUTED_LOCK_PREFIX = 'asf:distributed-lock:';

// ============================================================================
// Pub/Sub Channels
// ============================================================================

export const REDIS_SECURITY_CHANNEL = 'asf:security-events';

export const REDIS_AUTH_CHANNEL = 'asf:auth-events';

export const REDIS_GATEWAY_CHANNEL = 'asf:gateway-events';

export const REDIS_MONITORING_CHANNEL = 'asf:monitoring-events';

// ============================================================================
// Default TTL Values (Seconds)
// ============================================================================

export const DEFAULT_CACHE_TTL = 300;

export const DEFAULT_SESSION_TTL = 86400;

export const DEFAULT_REFRESH_TOKEN_TTL = 604800;

export const DEFAULT_RATE_LIMIT_TTL = 60;

export const DEFAULT_LOCK_TTL = 30;

// ============================================================================
// Redis Health Check
// ============================================================================

export const REDIS_HEALTH_KEY = 'asf:health';

// ============================================================================
// Redis Events
// ============================================================================

export const REDIS_EVENTS = {
  CONNECT: 'connect',

  READY: 'ready',

  ERROR: 'error',

  CLOSE: 'close',

  RECONNECTING: 'reconnecting',

  END: 'end',
} as const;

// ============================================================================
// Redis Scan Patterns
// ============================================================================

export const REDIS_SCAN_PATTERNS = {
  SESSIONS: 'asf:session:*',

  CACHE: 'asf:cache:*',

  RATE_LIMIT: 'asf:ratelimit:*',

  LOCKS: 'asf:lock:*',
} as const;

// ============================================================================
// End Of Redis Constants
// ============================================================================
