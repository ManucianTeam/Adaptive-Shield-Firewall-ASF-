/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Behavioral Fingerprint Interface Layer
 * File: fingerprint.interface.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines deterministic behavioral fingerprint
 * contracts used across ASF threat-intelligence,
 * anomaly-detection, and adaptive risk pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Establish request identity continuity
 * - Support probabilistic trust scoring
 * - Enable anomaly correlation
 * - Reduce replay-attack effectiveness
 * - Improve behavioral telemetry accuracy
 *
 * DESIGN PRINCIPLES:
 * - Immutable identity snapshots
 * - Lightweight serialization
 * - Distributed-system compatibility
 * - Zero-trust behavioral modeling
 * - High observability integration
 *
 * IMPORTANT:
 * Fingerprints are probabilistic signals.
 *
 * NEVER:
 * - treat fingerprints as absolute identity
 * - rely solely on IP-based attribution
 * - trust client-provided entropy blindly
 * - expose fingerprint internals publicly
 *
 * ============================================================
 */

/**
 * ============================================================
 * Geographic Topology Metadata
 * ============================================================
 *
 * PURPOSE:
 * Represents lightweight network-origin context
 * used for anomaly scoring and trust evaluation.
 * ============================================================
 */

export interface FingerprintGeoMetadata {
  country?: string;

  region?: string;

  city?: string;

  timezone?: string;

  autonomousSystem?: string;
}

/**
 * ============================================================
 * Device Capability Metadata
 * ============================================================
 *
 * PURPOSE:
 * Represents normalized client capability
 * information used for entropy modeling.
 * ============================================================
 */

export interface FingerprintDeviceMetadata {
  platform?: string;

  architecture?: string;

  browser?: string;

  browserVersion?: string;

  engine?: string;

  deviceType?: string;

  mobile?: boolean;

  language?: string;
}

/**
 * ============================================================
 * Behavioral Request Metadata
 * ============================================================
 *
 * PURPOSE:
 * Captures temporal and behavioral request
 * characteristics for adaptive scoring.
 * ============================================================
 */

export interface FingerprintBehaviorMetadata {
  requestVelocity?: number;

  averageIntervalMs?: number;

  concurrencyLevel?: number;

  sessionDurationMs?: number;

  repeatedPatternDetected?: boolean;

  anomalyScore?: number;
}

/**
 * ============================================================
 * Fingerprint Entropy Metrics
 * ============================================================
 *
 * PURPOSE:
 * Represents entropy-distribution signals used
 * for probabilistic identity uniqueness scoring.
 * ============================================================
 */

export interface FingerprintEntropyMetrics {
  headerEntropy?: number;

  agentEntropy?: number;

  timingEntropy?: number;

  behavioralEntropy?: number;

  compositeEntropy?: number;
}

/**
 * ============================================================
 * Primary Behavioral Fingerprint Contract
 * ============================================================
 *
 * PURPOSE:
 * Represents normalized request identity context
 * across ASF distributed security pipelines.
 *
 * USED BY:
 * - risk-scoring engines
 * - anomaly detectors
 * - telemetry pipelines
 * - replay detection systems
 * - adaptive policy engines
 * ============================================================
 */

export interface Fingerprint {
  /**
   * ==========================================================
   * Fingerprint Identifier
   * ==========================================================
   *
   * Deterministic or probabilistic identifier
   * generated from normalized request signals.
   * ==========================================================
   */

  id: string;

  /**
   * ==========================================================
   * Request Network Identity
   * ==========================================================
   */

  ipAddress: string;

  forwardedFor?: string[];

  /**
   * ==========================================================
   * User-Agent & Header Identity
   * ==========================================================
   */

  userAgent: string;

  acceptLanguage?: string;

  acceptEncoding?: string;

  /**
   * ==========================================================
   * Temporal Metadata
   * ==========================================================
   */

  timestamp: number;

  requestPath?: string;

  requestMethod?: string;

  /**
   * ==========================================================
   * Session Continuity
   * ==========================================================
   */

  sessionId?: string;

  correlationId?: string;

  requestId?: string;

  /**
   * ==========================================================
   * Geographic Context
   * ==========================================================
   */

  geo?: FingerprintGeoMetadata;

  /**
   * ==========================================================
   * Device Metadata
   * ==========================================================
   */

  device?: FingerprintDeviceMetadata;

  /**
   * ==========================================================
   * Behavioral Metadata
   * ==========================================================
   */

  behavior?: FingerprintBehaviorMetadata;

  /**
   * ==========================================================
   * Entropy Metrics
   * ==========================================================
   */

  entropy?: FingerprintEntropyMetrics;

  /**
   * ==========================================================
   * Security Signals
   * ==========================================================
   */

  suspicious?: boolean;

  botProbability?: number;

  trustScore?: number;

  riskScore?: number;

  replayRisk?: number;

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
   * Raw Header Snapshot
   * ==========================================================
   *
   * IMPORTANT:
   * Sensitive headers SHOULD be filtered
   * before persistence or telemetry export.
   * ==========================================================
   */

  headers?: Record<string, string>;

  /**
   * ==========================================================
   * Arbitrary Security Metadata
   * ==========================================================
   *
   * Used for:
   * - adaptive scoring extensions
   * - AI enrichment pipelines
   * - future telemetry integrations
   * ==========================================================
   */

  metadata?: Record<string, unknown>;
}
