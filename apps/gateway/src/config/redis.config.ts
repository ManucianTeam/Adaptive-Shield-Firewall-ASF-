// apps/gateway/src/config/redis.config.ts

import { registerAs } from '@nestjs/config';

// ============================================================================
// Redis Configuration
// ============================================================================
//
// Purpose:
//   Centralized Redis configuration for the ASF Gateway.
//
// Responsibilities:
//   - Redis connection settings
//   - Cache infrastructure
//   - Session storage
//   - Distributed locking
//   - Rate-limit synchronization
//   - Pub/Sub messaging
//
// Security Notes:
//   - Never hardcode Redis credentials.
//   - Production deployments should enable AUTH.
//   - TLS should be enabled in cloud environments.
//   - Restrict Redis network exposure.
//
// Supported Providers:
//   - Local Redis
//   - Docker Redis
//   - AWS ElastiCache
//   - Redis Cloud
//   - Azure Cache for Redis
//
// ============================================================================

export default registerAs(
  'redis',

  () => ({
    // ==========================================================================
    // Core Connection
    // ==========================================================================

    host: process.env.REDIS_HOST || 'localhost',

    port: parseInt(process.env.REDIS_PORT || '6379', 10),

    password: process.env.REDIS_PASSWORD || undefined,

    username: process.env.REDIS_USERNAME || undefined,

    // ==========================================================================
    // Database Selection
    // ==========================================================================

    db: parseInt(process.env.REDIS_DB || '0', 10),

    // ==========================================================================
    // Connection Security
    // ==========================================================================

    tls: process.env.REDIS_TLS === 'true',

    // ==========================================================================
    // Timeouts
    // ==========================================================================

    connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT || '10000', 10),

    commandTimeout: parseInt(process.env.REDIS_COMMAND_TIMEOUT || '5000', 10),

    // ==========================================================================
    // Retry Strategy
    // ==========================================================================

    retryStrategy: {
      maxRetriesPerRequest: parseInt(process.env.REDIS_MAX_RETRIES || '3', 10),

      retryDelay: parseInt(process.env.REDIS_RETRY_DELAY || '2000', 10),
    },

    // ==========================================================================
    // Connection Pool
    // ==========================================================================

    pool: {
      min: parseInt(process.env.REDIS_POOL_MIN || '2', 10),

      max: parseInt(process.env.REDIS_POOL_MAX || '10', 10),
    },

    // ==========================================================================
    // Cache TTL Defaults
    // ==========================================================================

    cache: {
      defaultTTL: parseInt(process.env.REDIS_DEFAULT_TTL || '300', 10),

      sessionTTL: parseInt(process.env.REDIS_SESSION_TTL || '86400', 10),
    },

    // ==========================================================================
    // Key Prefixes
    // ==========================================================================

    prefixes: {
      session: process.env.REDIS_SESSION_PREFIX || 'asf:session:',

      cache: process.env.REDIS_CACHE_PREFIX || 'asf:cache:',

      rateLimit: process.env.REDIS_RATE_LIMIT_PREFIX || 'asf:ratelimit:',

      lock: process.env.REDIS_LOCK_PREFIX || 'asf:lock:',
    },

    // ==========================================================================
    // Pub/Sub Channels
    // ==========================================================================

    pubsub: {
      securityEvents:
        process.env.REDIS_SECURITY_CHANNEL || 'asf:security-events',

      authEvents: process.env.REDIS_AUTH_CHANNEL || 'asf:auth-events',
    },
  }),
);
