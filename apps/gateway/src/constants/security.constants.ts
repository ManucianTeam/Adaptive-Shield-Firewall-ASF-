// apps/gateway/src/security/security.constants.ts

// ============================================================================
// ASF Security Constants
// ============================================================================
//
// Purpose:
//   Centralized security-related constants for the
//   Adaptive Shield Firewall (ASF) Gateway.
//
// Responsibilities:
//   - Security headers
//   - Risk levels
//   - Threat classifications
//   - Authentication constants
//   - Security event names
//   - Fingerprinting metadata
//   - Default policy values
//
// Security Philosophy:
//   "Security is enforced consistently through centralized policy."
//
// ============================================================================

// ============================================================================
// Security Headers
// ============================================================================

export const SECURITY_HEADERS = {
  FRAME_OPTIONS: 'X-Frame-Options',

  CONTENT_TYPE_OPTIONS: 'X-Content-Type-Options',

  XSS_PROTECTION: 'X-XSS-Protection',

  REFERRER_POLICY: 'Referrer-Policy',

  CONTENT_SECURITY_POLICY: 'Content-Security-Policy',

  STRICT_TRANSPORT_SECURITY: 'Strict-Transport-Security',

  PERMISSIONS_POLICY: 'Permissions-Policy',

  DEVICE_FINGERPRINT: 'X-Device-Fingerprint',

  REQUEST_ID: 'X-Request-Id',
} as const;

// ============================================================================
// Helmet Policies
// ============================================================================

export const HELMET_POLICIES = {
  FRAME_OPTIONS: 'DENY',

  REFERRER_POLICY: 'no-referrer',

  XSS_PROTECTION: '1; mode=block',
} as const;

// ============================================================================
// Authentication Constants
// ============================================================================

export const AUTH_CONSTANTS = {
  ACCESS_TOKEN_COOKIE: 'asf_access_token',

  REFRESH_TOKEN_COOKIE: 'asf_refresh_token',

  SESSION_COOKIE: 'asf_session',

  AUTHORIZATION_HEADER: 'authorization',

  BEARER_PREFIX: 'Bearer',
} as const;

// ============================================================================
// Security Risk Levels
// ============================================================================

export enum SecurityRiskLevel {
  LOW = 'LOW',

  MEDIUM = 'MEDIUM',

  HIGH = 'HIGH',

  CRITICAL = 'CRITICAL',
}

// ============================================================================
// Threat Categories
// ============================================================================

export enum ThreatCategory {
  BRUTE_FORCE = 'BRUTE_FORCE',

  TOKEN_ABUSE = 'TOKEN_ABUSE',

  RATE_LIMIT_ABUSE = 'RATE_LIMIT_ABUSE',

  ANOMALY_DETECTED = 'ANOMALY_DETECTED',

  BOT_ACTIVITY = 'BOT_ACTIVITY',

  SUSPICIOUS_IP = 'SUSPICIOUS_IP',

  SESSION_HIJACK = 'SESSION_HIJACK',

  FINGERPRINT_MISMATCH = 'FINGERPRINT_MISMATCH',

  CREDENTIAL_STUFFING = 'CREDENTIAL_STUFFING',
}

// ============================================================================
// Security Event Names
// ============================================================================

export const SECURITY_EVENTS = {
  LOGIN_SUCCESS: 'security.login.success',

  LOGIN_FAILED: 'security.login.failed',

  ACCOUNT_LOCKED: 'security.account.locked',

  TOKEN_REFRESH: 'security.token.refresh',

  TOKEN_REVOKED: 'security.token.revoked',

  SUSPICIOUS_REQUEST: 'security.suspicious.request',

  ANOMALY_DETECTED: 'security.anomaly.detected',

  RATE_LIMIT_EXCEEDED: 'security.rate-limit.exceeded',

  BRUTE_FORCE_DETECTED: 'security.brute-force.detected',

  IP_BLOCKED: 'security.ip.blocked',
} as const;

// ============================================================================
// Device Fingerprinting
// ============================================================================

export const FINGERPRINT = {
  HEADER_NAME: 'X-Device-Fingerprint',

  MAX_LENGTH: 512,

  HASH_ALGORITHM: 'sha256',
} as const;

// ============================================================================
// Rate Limiting Defaults
// ============================================================================

export const RATE_LIMIT = {
  GLOBAL_LIMIT: 100,

  GLOBAL_TTL: 60,

  AUTH_LIMIT: 10,

  AUTH_TTL: 60,

  SENSITIVE_LIMIT: 20,

  SENSITIVE_TTL: 300,
} as const;

// ============================================================================
// Brute Force Protection
// ============================================================================

export const BRUTE_FORCE = {
  MAX_ATTEMPTS: 5,

  BLOCK_DURATION: 900,

  RESET_WINDOW: 3600,
} as const;

// ============================================================================
// Password Policy
// ============================================================================

export const PASSWORD_POLICY = {
  MIN_LENGTH: 8,

  MAX_LENGTH: 128,

  REQUIRE_UPPERCASE: true,

  REQUIRE_LOWERCASE: true,

  REQUIRE_NUMBER: true,

  REQUIRE_SPECIAL_CHARACTER: true,
} as const;

// ============================================================================
// Request Constraints
// ============================================================================

export const REQUEST_LIMITS = {
  MAX_BODY_SIZE: '1mb',

  MAX_JSON_SIZE: '1mb',

  MAX_URL_LENGTH: 2048,

  MAX_HEADERS_COUNT: 100,
} as const;

// ============================================================================
// Trusted Proxy Headers
// ============================================================================

export const TRUSTED_PROXY_HEADERS = [
  'x-forwarded-for',

  'x-forwarded-host',

  'x-forwarded-proto',

  'cf-connecting-ip',
] as const;

// ============================================================================
// Security Monitoring
// ============================================================================

export const SECURITY_MONITORING = {
  LOG_SUSPICIOUS_REQUESTS: true,

  LOG_FAILED_LOGINS: true,

  LOG_TOKEN_ABUSE: true,

  ENABLE_REALTIME_ALERTS: true,
} as const;

// ============================================================================
// Default Security Scores
// ============================================================================

export const SECURITY_SCORE = {
  SAFE: 0,

  LOW_RISK: 25,

  MEDIUM_RISK: 50,

  HIGH_RISK: 75,

  CRITICAL_RISK: 100,
} as const;

// ============================================================================
// End Of Security Constants
// ============================================================================
