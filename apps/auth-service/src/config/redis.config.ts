// apps/auth-service/src/config/redis.config.ts

import { registerAs } from '@nestjs/config';

/**
 * ============================================================================
 * ASF Redis Configuration
 * ============================================================================
 *
 * Enterprise-grade Redis configuration layer engineered for distributed
 * authentication infrastructures and adaptive Zero Trust platforms.
 *
 * Core Responsibilities:
 *
 *  - distributed cache configuration
 *  - session-store orchestration
 *  - pub/sub infrastructure tuning
 *  - connection resilience management
 *  - rate-limit persistence
 *  - distributed lock coordination
 *
 * Security Architecture:
 *
 *  - environment-isolated connectivity
 *  - authenticated Redis access
 *  - TLS-ready deployment model
 *  - namespace segmentation
 *  - distributed session hardening
 *  - fault-tolerant connection recovery
 *
 * Designed For:
 *
 *  - distributed authentication systems
 *  - API gateway infrastructures
 *  - high-concurrency microservices
 *  - adaptive access-control platforms
 *  - AI-assisted threat telemetry
 *
 * Integrated Domains:
 *
 *  - distributed sessions
 *  - JWT correlation
 *  - request throttling
 *  - device fingerprint persistence
 *  - adaptive threat scoring
 *  - distributed locking
 *
 * ============================================================================
 */

export default registerAs(
  'redis',

  () => ({
    /**
     * ------------------------------------------------------------------------
     * Primary Connectivity
     * ------------------------------------------------------------------------
     */

    host:
      process.env.REDIS_HOST ||
      'localhost',

    port:
      Number(
        process.env.REDIS_PORT ||
        6379,
      ),

    /**
     * ------------------------------------------------------------------------
     * Authentication
     * ------------------------------------------------------------------------
     */

    password:
      process.env.REDIS_PASSWORD ||
      undefined,

    username:
      process.env.REDIS_USERNAME ||
      undefined,

    /**
     * ------------------------------------------------------------------------
     * Logical Database Isolation
     * ------------------------------------------------------------------------
     */

    db:
      Number(
        process.env.REDIS_DB ||
        0,
      ),

    /**
     * ------------------------------------------------------------------------
     * Connection Resilience
     * ------------------------------------------------------------------------
     */

    connectTimeout:
      Number(
        process.env
          .REDIS_CONNECT_TIMEOUT ||
          10000,
      ),

    maxRetriesPerRequest:
      Number(
        process.env
          .REDIS_MAX_RETRIES ||
          3,
      ),

    retryStrategy: (
      attempts: number,
    ) =>
      Math.min(
        attempts * 500,
        5000,
      ),

    /**
     * ------------------------------------------------------------------------
     * Distributed Session Hardening
     * ------------------------------------------------------------------------
     */

    keyPrefix:
      process.env.REDIS_PREFIX ||
      'asf:',

    /**
     * ------------------------------------------------------------------------
     * TLS / SSL Infrastructure
     * ------------------------------------------------------------------------
     */

    tls:
      process.env.REDIS_TLS ===
      'true'
        ? {
            rejectUnauthorized:
              false,
          }
        : undefined,

    /**
     * ------------------------------------------------------------------------
     * High-Availability Infrastructure
     * ------------------------------------------------------------------------
     */

    enableReadyCheck:
      true,

    enableOfflineQueue:
      true,

    lazyConnect:
      true,

    /**
     * ------------------------------------------------------------------------
     * Connection Pool Optimization
     * ------------------------------------------------------------------------
     */

    family:
      4,

    keepAlive:
      Number(
        process.env
          .REDIS_KEEP_ALIVE ||
          30000,
      ),

    /**
     * ------------------------------------------------------------------------
     * Distributed Pub/Sub Channels
     * ------------------------------------------------------------------------
     */

    channels: {
      AUTH_EVENTS:
        'asf:auth:events',

      SECURITY_EVENTS:
        'asf:security:events',

      SESSION_EVENTS:
        'asf:session:events',

      THREAT_EVENTS:
        'asf:threat:events',
    },

    /**
     * ------------------------------------------------------------------------
     * Cache TTL Policies
     * ------------------------------------------------------------------------
     */

    ttl: {
      SESSION:
        60 * 60 * 24 * 7,

      RATE_LIMIT:
        60,

      THREAT_ANALYSIS:
        60 * 10,

      DEVICE_FINGERPRINT:
        60 * 60 * 24 * 30,

      TOKEN_BLACKLIST:
        60 * 60 * 24,
    },

    /**
     * ------------------------------------------------------------------------
     * Distributed Locking
     * ------------------------------------------------------------------------
     */

    locks: {
      SESSION_LOCK_TTL:
        5000,

      AUTH_LOCK_TTL:
        3000,

      RATE_LIMIT_LOCK_TTL:
        1000,
    },
  }),
);