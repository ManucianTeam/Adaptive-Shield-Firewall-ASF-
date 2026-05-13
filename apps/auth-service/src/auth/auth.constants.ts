// apps/auth-service/src/auth/auth.constants.ts

/**
 * ============================================================================
 * ASF Authentication Constants
 * ============================================================================
 *
 * Centralized authentication-security constants engineered for distributed
 * Zero Trust infrastructures and adaptive identity-management systems.
 *
 * Core Domains:
 *
 *  - JWT lifecycle configuration
 *  - Redis namespace isolation
 *  - session hardening policies
 *  - adaptive risk thresholds
 *  - distributed security metadata
 *  - AI-assisted threat scoring
 *
 * Design Goals:
 *
 *  - deterministic security configuration
 *  - strongly typed authentication domains
 *  - cross-module consistency
 *  - scalable distributed integration
 *  - centralized runtime tuning
 *
 * ============================================================================
 */

/**
 * --------------------------------------------------------------------------
 * JWT Strategy Names
 * --------------------------------------------------------------------------
 */

export const AUTH_STRATEGIES = {
  ACCESS_JWT:
    'jwt',

  REFRESH_JWT:
    'jwt-refresh',
} as const;

/**
 * --------------------------------------------------------------------------
 * Redis Namespace Isolation
 * --------------------------------------------------------------------------
 */

export const REDIS_KEYS = {
  SESSION:
    'auth:session',

  REFRESH:
    'auth:refresh',

  RATE_LIMIT:
    'auth:rate-limit',

  LOGIN_ATTEMPT:
    'auth:login-attempt',

  DEVICE_FINGERPRINT:
    'auth:fingerprint',

  RISK_SCORE:
    'auth:risk-score',

  THREAT_ANALYSIS:
    'auth:threat-analysis',
} as const;

/**
 * --------------------------------------------------------------------------
 * JWT Expiration Policies
 * --------------------------------------------------------------------------
 */

export const TOKEN_TTL = {
  ACCESS_TOKEN:
    '15m',

  REFRESH_TOKEN:
    '7d',

  PASSWORD_RESET:
    '15m',

  EMAIL_VERIFICATION:
    '1d',
} as const;

/**
 * --------------------------------------------------------------------------
 * Session Security Policies
 * --------------------------------------------------------------------------
 */

export const SESSION_SECURITY = {
  MAX_CONCURRENT_SESSIONS:
    5,

  SESSION_TTL_SECONDS:
    60 * 60 * 24 * 7,

  IDLE_TIMEOUT_SECONDS:
    60 * 30,

  ABSOLUTE_TIMEOUT_SECONDS:
    60 * 60 * 24 * 30,

  REFRESH_ROTATION_ENABLED:
    true,

  REQUIRE_DEVICE_FINGERPRINT:
    true,
} as const;

/**
 * --------------------------------------------------------------------------
 * Adaptive Threat Thresholds
 * --------------------------------------------------------------------------
 */

export const RISK_THRESHOLDS = {
  LOW:
    20,

  MEDIUM:
    45,

  HIGH:
    70,

  CRITICAL:
    90,
} as const;

/**
 * --------------------------------------------------------------------------
 * AI Behavioral Analysis Policies
 * --------------------------------------------------------------------------
 */

export const AI_SECURITY = {
  MAX_LOGIN_VELOCITY:
    10,

  GEO_DISTANCE_LIMIT_KM:
    2000,

  IMPOSSIBLE_TRAVEL_WINDOW_MIN:
    30,

  MAX_DEVICE_VARIATIONS:
    5,

  MAX_REQUEST_BURST:
    120,

  TIMING_ANOMALY_THRESHOLD:
    0.85,
} as const;

/**
 * --------------------------------------------------------------------------
 * Password Hardening Policies
 * --------------------------------------------------------------------------
 */

export const PASSWORD_POLICY = {
  MIN_LENGTH:
    10,

  MAX_LENGTH:
    128,

  REQUIRE_UPPERCASE:
    true,

  REQUIRE_LOWERCASE:
    true,

  REQUIRE_NUMERIC:
    true,

  REQUIRE_SPECIAL:
    true,

  MIN_ENTROPY:
    50,

  ROTATION_DAYS:
    90,

  BCRYPT_ROUNDS:
    12,
} as const;

/**
 * --------------------------------------------------------------------------
 * Distributed Rate-Limit Policies
 * --------------------------------------------------------------------------
 */

export const RATE_LIMITS = {
  LOGIN_ATTEMPTS:
    {
      LIMIT: 5,
      WINDOW_SECONDS: 60,
    },

  REGISTER_ATTEMPTS:
    {
      LIMIT: 3,
      WINDOW_SECONDS: 300,
    },

  PASSWORD_RESET:
    {
      LIMIT: 3,
      WINDOW_SECONDS: 600,
    },

  TOKEN_REFRESH:
    {
      LIMIT: 20,
      WINDOW_SECONDS: 60,
    },
} as const;

/**
 * --------------------------------------------------------------------------
 * Authentication Event Domains
 * --------------------------------------------------------------------------
 */

export const AUTH_EVENTS = {
  LOGIN_SUCCESS:
    'auth.login.success',

  LOGIN_FAILED:
    'auth.login.failed',

  LOGIN_SUSPICIOUS:
    'auth.login.suspicious',

  TOKEN_REFRESHED:
    'auth.token.refreshed',

  SESSION_REVOKED:
    'auth.session.revoked',

  PASSWORD_RESET_REQUESTED:
    'auth.password.reset.requested',

  PASSWORD_CHANGED:
    'auth.password.changed',
} as const;

/**
 * --------------------------------------------------------------------------
 * Trust Classification Levels
 * --------------------------------------------------------------------------
 */

export const TRUST_LEVELS = {
  FULLY_TRUSTED:
    100,

  TRUSTED:
    80,

  MONITORED:
    60,

  RESTRICTED:
    40,

  HIGH_RISK:
    20,

  BLOCKED:
    0,
} as const;

/**
 * --------------------------------------------------------------------------
 * Authentication Role Domains
 * --------------------------------------------------------------------------
 */

export const AUTH_ROLES = {
  ADMIN:
    'admin',

  USER:
    'user',

  MODERATOR:
    'moderator',

  SECURITY_ANALYST:
    'security-analyst',

  SYSTEM:
    'system',
} as const;