// apps/gateway/src/security/threat.constants.ts

// ============================================================================
// ASF Threat Intelligence Constants
// ============================================================================
//
// Purpose:
//   Centralized threat intelligence definitions for the
//   Adaptive Shield Firewall (ASF) Gateway.
//
// Responsibilities:
//   - Threat classifications
//   - Detection thresholds
//   - Risk scoring
//   - Attack signatures
//   - Automated response policies
//   - Security escalation rules
//
// Architecture:
//   Used by:
//     - AI Security Engine
//     - Anomaly Detection
//     - Gateway Middleware
//     - Rate Limiting Layer
//     - Intrusion Detection Services
//
// Security Philosophy:
//   "Threats are evaluated continuously, not statically."
//
// ============================================================================

// ============================================================================
// Threat Severity Levels
// ============================================================================

export enum ThreatSeverity {
  INFO = 'INFO',

  LOW = 'LOW',

  MEDIUM = 'MEDIUM',

  HIGH = 'HIGH',

  CRITICAL = 'CRITICAL',
}

// ============================================================================
// Threat Categories
// ============================================================================

export enum ThreatType {
  BRUTE_FORCE = 'BRUTE_FORCE',

  DDoS = 'DDOS',

  BOT_ACTIVITY = 'BOT_ACTIVITY',

  TOKEN_ABUSE = 'TOKEN_ABUSE',

  SESSION_HIJACK = 'SESSION_HIJACK',

  CREDENTIAL_STUFFING = 'CREDENTIAL_STUFFING',

  SQL_INJECTION = 'SQL_INJECTION',

  XSS_ATTACK = 'XSS_ATTACK',

  CSRF_ATTACK = 'CSRF_ATTACK',

  API_ABUSE = 'API_ABUSE',

  SUSPICIOUS_IP = 'SUSPICIOUS_IP',

  GEO_ANOMALY = 'GEO_ANOMALY',

  RATE_LIMIT_BYPASS = 'RATE_LIMIT_BYPASS',

  FINGERPRINT_SPOOFING = 'FINGERPRINT_SPOOFING',

  UNKNOWN = 'UNKNOWN',
}

// ============================================================================
// Threat Risk Scores
// ============================================================================

export const THREAT_RISK_SCORE = {
  SAFE: 0,

  LOW: 20,

  MEDIUM: 50,

  HIGH: 80,

  CRITICAL: 100,
} as const;

// ============================================================================
// Automated Response Actions
// ============================================================================

export enum ThreatResponseAction {
  ALLOW = 'ALLOW',

  MONITOR = 'MONITOR',

  CHALLENGE = 'CHALLENGE',

  RATE_LIMIT = 'RATE_LIMIT',

  TEMP_BLOCK = 'TEMP_BLOCK',

  PERMANENT_BLOCK = 'PERMANENT_BLOCK',

  REQUIRE_REAUTH = 'REQUIRE_REAUTH',
}

// ============================================================================
// Brute Force Detection
// ============================================================================

export const BRUTE_FORCE_THRESHOLDS = {
  MAX_LOGIN_ATTEMPTS: 5,

  WINDOW_SECONDS: 300,

  BLOCK_DURATION_SECONDS: 900,

  ESCALATION_THRESHOLD: 15,
} as const;

// ============================================================================
// DDoS Detection
// ============================================================================

export const DDOS_THRESHOLDS = {
  REQUESTS_PER_SECOND: 100,

  BURST_LIMIT: 300,

  CONNECTION_LIMIT: 500,

  BLOCK_DURATION_SECONDS: 1800,
} as const;

// ============================================================================
// Bot Detection Signals
// ============================================================================

export const BOT_DETECTION = {
  MAX_REQUEST_INTERVAL_MS: 50,

  MIN_MOUSE_MOVEMENT_SCORE: 0.2,

  MAX_REPETITIVE_ACTIONS: 20,

  HEADLESS_BROWSER_SCORE: 0.9,
} as const;

// ============================================================================
// Session Hijacking Detection
// ============================================================================

export const SESSION_SECURITY = {
  MAX_IP_CHANGES: 3,

  MAX_DEVICE_CHANGES: 2,

  GEO_DISTANCE_THRESHOLD_KM: 1000,

  SESSION_REVALIDATION_INTERVAL: 1800,
} as const;

// ============================================================================
// Fingerprint Validation
// ============================================================================

export const FINGERPRINT_SECURITY = {
  MIN_FINGERPRINT_LENGTH: 32,

  MAX_FINGERPRINT_AGE: 86400,

  MAX_MISMATCH_SCORE: 0.7,
} as const;

// ============================================================================
// SQL Injection Patterns
// ============================================================================

export const SQL_INJECTION_PATTERNS = [
  '--',

  ';--',

  'DROP TABLE',

  'UNION SELECT',

  ' OR 1=1',

  "' OR '1'='1",

  'xp_cmdshell',
] as const;

// ============================================================================
// XSS Attack Patterns
// ============================================================================

export const XSS_PATTERNS = [
  '<script',

  'javascript:',

  'onerror=',

  'onload=',

  'alert(',

  'document.cookie',

  '<iframe',
] as const;

// ============================================================================
// Suspicious User Agents
// ============================================================================

export const SUSPICIOUS_USER_AGENTS = [
  'sqlmap',

  'nikto',

  'curl',

  'wget',

  'python-requests',

  'axios',

  'postmanruntime',
] as const;

// ============================================================================
// Threat Escalation Rules
// ============================================================================

export const THREAT_ESCALATION = {
  LOW_TO_MEDIUM: 3,

  MEDIUM_TO_HIGH: 5,

  HIGH_TO_CRITICAL: 10,
} as const;

// ============================================================================
// AI Security Thresholds
// ============================================================================

export const AI_SECURITY_THRESHOLDS = {
  ANOMALY_LOW: 0.3,

  ANOMALY_MEDIUM: 0.6,

  ANOMALY_HIGH: 0.8,

  ANOMALY_CRITICAL: 0.95,
} as const;

// ============================================================================
// Threat Monitoring Channels
// ============================================================================

export const THREAT_CHANNELS = {
  SECURITY_ALERTS: 'asf:threat:alerts',

  INCIDENTS: 'asf:threat:incidents',

  ANOMALIES: 'asf:threat:anomalies',

  BLOCKED_IPS: 'asf:threat:blocked-ips',
} as const;

// ============================================================================
// Threat Intelligence Cache TTL
// ============================================================================

export const THREAT_CACHE_TTL = {
  IP_REPUTATION: 3600,

  THREAT_SIGNATURES: 86400,

  GEO_LOCATION: 43200,

  SESSION_RISK: 1800,
} as const;

// ============================================================================
// End Of Threat Constants
// ============================================================================
