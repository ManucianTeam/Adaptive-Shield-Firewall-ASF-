/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Threat Intelligence Interface Layer
 * File: threat.interface.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines normalized threat-intelligence contracts
 * used throughout ASF behavioral-analysis,
 * anomaly-detection, and adaptive mitigation
 * pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Standardize threat representation
 * - Enable distributed threat correlation
 * - Support adaptive mitigation engines
 * - Improve forensic observability
 * - Strengthen behavioral anomaly detection
 *
 * DESIGN PRINCIPLES:
 * - Immutable threat snapshots
 * - Deterministic classification structures
 * - Lightweight serialization
 * - Distributed-system compatibility
 * - High telemetry interoperability
 *
 * IMPORTANT:
 * Threat objects represent probabilistic
 * security evaluations and MUST NOT be treated
 * as absolute proof of malicious intent.
 *
 * NEVER:
 * - rely on a single weak signal
 * - expose internal scoring heuristics
 * - persist sensitive secrets in threat objects
 * - trust unverified intelligence blindly
 *
 * ============================================================
 */

/**
 * ============================================================
 * Threat Severity Classification
 * ============================================================
 *
 * PURPOSE:
 * Represents normalized security impact levels
 * across ASF detection pipelines.
 * ============================================================
 */

export enum ThreatSeverity {
  LOW = 'low',

  MEDIUM = 'medium',

  HIGH = 'high',

  CRITICAL = 'critical',
}

/**
 * ============================================================
 * Threat Classification Types
 * ============================================================
 *
 * PURPOSE:
 * Represents normalized behavioral and
 * infrastructural threat categories.
 * ============================================================
 */

export enum ThreatType {
  BOT_ACTIVITY = 'bot_activity',

  CREDENTIAL_STUFFING = 'credential_stuffing',

  RATE_LIMIT_ABUSE = 'rate_limit_abuse',

  DISTRIBUTED_FLOODING = 'distributed_flooding',

  REPLAY_ATTACK = 'replay_attack',

  RACE_CONDITION_EXPLOIT = 'race_condition_exploit',

  SESSION_ANOMALY = 'session_anomaly',

  BEHAVIORAL_DEVIATION = 'behavioral_deviation',

  GEOLOCATION_ANOMALY = 'geolocation_anomaly',

  TOKEN_ABUSE = 'token_abuse',

  HEADER_MANIPULATION = 'header_manipulation',

  REQUEST_TAMPERING = 'request_tampering',

  RECONNAISSANCE_ACTIVITY = 'reconnaissance_activity',

  UNKNOWN = 'unknown',
}

/**
 * ============================================================
 * Threat Confidence Metadata
 * ============================================================
 *
 * PURPOSE:
 * Represents probabilistic evaluation metadata
 * used for adaptive scoring decisions.
 * ============================================================
 */

export interface ThreatConfidence {
  score: number;

  confidence: number;

  falsePositiveProbability?: number;

  behavioralWeight?: number;

  anomalyWeight?: number;

  concurrencyWeight?: number;

  entropyWeight?: number;
}

/**
 * ============================================================
 * Threat Source Metadata
 * ============================================================
 *
 * PURPOSE:
 * Represents origin information associated
 * with detected threats.
 * ============================================================
 */

export interface ThreatSource {
  ipAddress?: string;

  forwardedFor?: string[];

  country?: string;

  region?: string;

  autonomousSystem?: string;

  userAgent?: string;

  deviceFingerprint?: string;

  sessionId?: string;

  requestId?: string;

  correlationId?: string;
}

/**
 * ============================================================
 * Threat Behavioral Metadata
 * ============================================================
 *
 * PURPOSE:
 * Represents behavioral-analysis outputs
 * associated with the threat event.
 * ============================================================
 */

export interface ThreatBehavior {
  requestVelocity?: number;

  concurrencyLevel?: number;

  repeatedPatternDetected?: boolean;

  anomalyScore?: number;

  entropyScore?: number;

  trustScore?: number;

  replayRisk?: number;

  botProbability?: number;
}

/**
 * ============================================================
 * Threat Mitigation Metadata
 * ============================================================
 *
 * PURPOSE:
 * Represents mitigation decisions generated
 * by ASF adaptive defense pipelines.
 * ============================================================
 */

export interface ThreatMitigation {
  blocked?: boolean;

  challenged?: boolean;

  rateLimited?: boolean;

  shadowBanned?: boolean;

  captchaRequired?: boolean;

  sessionRevoked?: boolean;

  mitigationStrategy?: string;

  mitigationReason?: string;
}

/**
 * ============================================================
 * Primary Threat Contract
 * ============================================================
 *
 * PURPOSE:
 * Represents normalized threat intelligence
 * events propagated throughout ASF systems.
 *
 * USED BY:
 * - anomaly engines
 * - adaptive mitigation systems
 * - telemetry pipelines
 * - SIEM integrations
 * - incident response workflows
 * ============================================================
 */

export interface Threat {
  /**
   * ==========================================================
   * Threat Identity
   * ==========================================================
   */

  id: string;

  type: ThreatType;

  severity: ThreatSeverity;

  /**
   * ==========================================================
   * Threat Description
   * ==========================================================
   */

  title: string;

  description?: string;

  /**
   * ==========================================================
   * Temporal Metadata
   * ==========================================================
   */

  detectedAt: number;

  lastObservedAt?: number;

  resolvedAt?: number;

  /**
   * ==========================================================
   * Threat Confidence
   * ==========================================================
   */

  confidence: ThreatConfidence;

  /**
   * ==========================================================
   * Threat Source
   * ==========================================================
   */

  source?: ThreatSource;

  /**
   * ==========================================================
   * Behavioral Metadata
   * ==========================================================
   */

  behavior?: ThreatBehavior;

  /**
   * ==========================================================
   * Mitigation Metadata
   * ==========================================================
   */

  mitigation?: ThreatMitigation;

  /**
   * ==========================================================
   * Infrastructure Metadata
   * ==========================================================
   */

  processingNode?: string;

  gatewayRegion?: string;

  serviceVersion?: string;

  /**
   * ==========================================================
   * Threat Intelligence Tags
   * ==========================================================
   */

  tags?: string[];

  /**
   * ==========================================================
   * Evidence Collection
   * ==========================================================
   *
   * IMPORTANT:
   * Evidence SHOULD be sanitized before
   * external export or persistence.
   * ==========================================================
   */

  evidence?: Record<string, unknown>;

  /**
   * ==========================================================
   * Arbitrary Threat Metadata
   * ==========================================================
   *
   * Used for:
   * - AI enrichment
   * - future detection modules
   * - telemetry extensions
   * - adaptive policy integrations
   * ==========================================================
   */

  metadata?: Record<string, unknown>;
}
