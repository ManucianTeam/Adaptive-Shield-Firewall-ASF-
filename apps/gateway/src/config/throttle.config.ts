// apps/gateway/src/config/throttle.config.ts

import { registerAs } from '@nestjs/config';

// ============================================================================
// ASF Gateway Throttling Configuration
// ============================================================================
//
// Purpose:
//   Centralized request throttling and abuse-prevention configuration
//   for the Adaptive Shield Firewall (ASF) Gateway.
//
// Responsibilities:
//   - Global request throttling
//   - Authentication endpoint protection
//   - API abuse mitigation
//   - DDoS resistance
//   - Burst traffic control
//   - Per-route rate profiles
//
// Security Philosophy:
//   Every request consumes trust.
//   Excessive behavior reduces trust.
//
// Recommended Production Strategy:
//   - Aggressive limits on auth routes
//   - Moderate limits on public APIs
//   - Strict limits on sensitive endpoints
//   - Redis-backed distributed throttling
//
// ============================================================================

export default registerAs(
  'throttle',

  () => ({
    // ==========================================================================
    // Global Throttling
    // ==========================================================================

    global: {
      enabled: process.env.THROTTLE_ENABLED !== 'false',

      ttl: parseInt(process.env.THROTTLE_GLOBAL_TTL || '60', 10),

      limit: parseInt(process.env.THROTTLE_GLOBAL_LIMIT || '100', 10),
    },

    // ==========================================================================
    // Authentication Endpoints
    // ==========================================================================
    //
    // Protects:
    //   - Login
    //   - Register
    //   - Forgot Password
    //   - Refresh Token
    //
    // ==========================================================================

    auth: {
      ttl: parseInt(process.env.THROTTLE_AUTH_TTL || '60', 10),

      limit: parseInt(process.env.THROTTLE_AUTH_LIMIT || '10', 10),

      blockDuration: parseInt(
        process.env.THROTTLE_AUTH_BLOCK_DURATION || '900',
        10,
      ),
    },

    // ==========================================================================
    // API Endpoints
    // ==========================================================================

    api: {
      ttl: parseInt(process.env.THROTTLE_API_TTL || '60', 10),

      limit: parseInt(process.env.THROTTLE_API_LIMIT || '200', 10),
    },

    // ==========================================================================
    // Sensitive Operations
    // ==========================================================================
    //
    // Examples:
    //   - Admin routes
    //   - Security routes
    //   - Payment routes
    //   - Account management
    //
    // ==========================================================================

    sensitive: {
      ttl: parseInt(process.env.THROTTLE_SENSITIVE_TTL || '300', 10),

      limit: parseInt(process.env.THROTTLE_SENSITIVE_LIMIT || '20', 10),
    },

    // ==========================================================================
    // Burst Protection
    // ==========================================================================
    //
    // Prevents ultra-fast request flooding.
    //
    // ==========================================================================

    burst: {
      ttl: parseInt(process.env.THROTTLE_BURST_TTL || '10', 10),

      limit: parseInt(process.env.THROTTLE_BURST_LIMIT || '30', 10),
    },

    // ==========================================================================
    // IP Blocking Policy
    // ==========================================================================

    blocking: {
      enabled: process.env.THROTTLE_BLOCKING_ENABLED !== 'false',

      temporaryBlockDuration: parseInt(
        process.env.THROTTLE_BLOCK_DURATION || '1800',
        10,
      ),
    },

    // ==========================================================================
    // Trusted Clients
    // ==========================================================================
    //
    // Internal services or trusted API consumers.
    //
    // Example:
    //   THROTTLE_TRUSTED_IPS=127.0.0.1,10.0.0.2
    //
    // ==========================================================================

    trusted: {
      ips: process.env.THROTTLE_TRUSTED_IPS?.split(',') || [],

      bypass: process.env.THROTTLE_TRUSTED_BYPASS === 'true',
    },

    // ==========================================================================
    // Redis Synchronization
    // ==========================================================================
    //
    // Enables distributed throttling across multiple nodes.
    //
    // ==========================================================================

    redis: {
      enabled: process.env.THROTTLE_REDIS_ENABLED === 'true',

      prefix: process.env.THROTTLE_REDIS_PREFIX || 'asf:throttle:',
    },

    // ==========================================================================
    // Monitoring & Logging
    // ==========================================================================

    monitoring: {
      logViolations: process.env.THROTTLE_LOG_VIOLATIONS !== 'false',

      logBlockedRequests: process.env.THROTTLE_LOG_BLOCKED !== 'false',
    },
  }),
);
