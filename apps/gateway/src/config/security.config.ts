// apps/gateway/src/config/security.config.ts

import { registerAs } from '@nestjs/config';

// ============================================================================
// ASF Gateway Security Configuration
// ============================================================================
//
// Purpose:
//   Centralized security policy configuration for the
//   Adaptive Shield Firewall (ASF) Gateway.
//
// Responsibilities:
//   - HTTP security headers
//   - Rate limiting policy
//   - Brute-force protection
//   - Request filtering
//   - IP trust rules
//   - Payload restrictions
//   - CORS hardening
//   - Session protection
//
// Security Philosophy:
//   ASF follows a Zero-Trust-inspired architecture:
//
//   "Every request is untrusted until verified."
//
// Production Recommendations:
//   - Use HTTPS only
//   - Enable secure cookies
//   - Restrict trusted origins
//   - Tune rate limits aggressively
//   - Enable reverse proxy trust
//
// ============================================================================

export default registerAs(
  'security',

  () => ({
    // ==========================================================================
    // Environment
    // ==========================================================================

    environment: process.env.NODE_ENV || 'development',

    // ==========================================================================
    // CORS Policy
    // ==========================================================================

    cors: {
      enabled: process.env.CORS_ENABLED === 'true',

      origin: process.env.CORS_ORIGIN || '*',

      credentials: process.env.CORS_CREDENTIALS === 'true',

      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-Forwarded-For',
        'X-Device-Fingerprint',
        'X-CSRF-Token',
      ],
    },

    // ==========================================================================
    // Helmet Security Headers
    // ==========================================================================

    helmet: {
      enabled: process.env.HELMET_ENABLED !== 'false',

      contentSecurityPolicy: process.env.CSP_ENABLED === 'true',

      crossOriginEmbedderPolicy: false,
    },

    // ==========================================================================
    // Rate Limiting
    // ==========================================================================

    rateLimit: {
      enabled: process.env.RATE_LIMIT_ENABLED !== 'false',

      ttl: parseInt(process.env.RATE_LIMIT_TTL || '60', 10),

      max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),

      authMax: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '10', 10),

      authTTL: parseInt(process.env.AUTH_RATE_LIMIT_TTL || '60', 10),
    },

    // ==========================================================================
    // Request Payload Protection
    // ==========================================================================

    payload: {
      maxBodySize: process.env.MAX_BODY_SIZE || '1mb',

      maxJsonSize: process.env.MAX_JSON_SIZE || '1mb',

      maxUrlEncodedSize: process.env.MAX_URLENCODED_SIZE || '1mb',
    },

    // ==========================================================================
    // Session Security
    // ==========================================================================

    session: {
      secureCookies: process.env.SECURE_COOKIES === 'true',

      httpOnly: process.env.HTTP_ONLY_COOKIES !== 'false',

      sameSite: process.env.COOKIE_SAMESITE || 'strict',
    },

    // ==========================================================================
    // Trusted Proxy
    // ==========================================================================

    trustProxy: process.env.TRUST_PROXY === 'true',

    // ==========================================================================
    // Request Fingerprinting
    // ==========================================================================

    fingerprinting: {
      enabled: process.env.FINGERPRINT_ENABLED !== 'false',

      headerName: process.env.FINGERPRINT_HEADER || 'X-Device-Fingerprint',
    },

    // ==========================================================================
    // Brute Force Protection
    // ==========================================================================

    bruteForce: {
      enabled: process.env.BRUTE_FORCE_ENABLED !== 'false',

      maxAttempts: parseInt(process.env.BRUTE_FORCE_MAX_ATTEMPTS || '5', 10),

      blockDuration: parseInt(
        process.env.BRUTE_FORCE_BLOCK_DURATION || '900',
        10,
      ),
    },

    // ==========================================================================
    // IP Reputation
    // ==========================================================================

    ipReputation: {
      enabled: process.env.IP_REPUTATION_ENABLED === 'true',

      strictMode: process.env.IP_REPUTATION_STRICT === 'true',
    },

    // ==========================================================================
    // AI Security Engine
    // ==========================================================================

    aiSecurity: {
      enabled: process.env.AI_SECURITY_ENABLED !== 'false',

      anomalyThreshold: parseFloat(process.env.AI_ANOMALY_THRESHOLD || '0.8'),

      autoBlock: process.env.AI_AUTO_BLOCK === 'true',
    },

    // ==========================================================================
    // Logging & Monitoring
    // ==========================================================================

    monitoring: {
      logSuspiciousRequests: process.env.LOG_SUSPICIOUS_REQUESTS !== 'false',

      logAuthAttempts: process.env.LOG_AUTH_ATTEMPTS !== 'false',
    },
  }),
);
