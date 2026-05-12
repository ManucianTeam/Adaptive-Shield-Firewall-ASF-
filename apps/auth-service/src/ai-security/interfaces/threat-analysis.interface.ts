// apps/auth-service/src/ai-security/interfaces/threat-analysis.interface.ts

/**
 * ============================================================================
 * ASF AI Security — Threat Analysis Interface
 * ============================================================================
 *
 * Unified threat intelligence contract shared across:
 *
 *  - anomaly analyzers
 *  - behavioral analyzers
 *  - geospatial analyzers
 *  - timing analyzers
 *  - adaptive security middleware
 *  - distributed risk orchestration services
 *
 * This interface standardizes the structure of security telemetry,
 * enabling deterministic aggregation, AI-assisted scoring,
 * distributed event streaming, and cross-analyzer correlation.
 *
 * The architecture is intentionally extensible for future integration with:
 *
 *  - ML inference pipelines
 *  - SIEM platforms
 *  - real-time threat graphs
 *  - federated trust systems
 *  - adaptive authentication engines
 *
 * ============================================================================
 */

/**
 * --------------------------------------------------------------------------
 * Core Threat Severity
 * --------------------------------------------------------------------------
 */

export type ThreatSeverity =
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

/**
 * --------------------------------------------------------------------------
 * Threat Classification
 * --------------------------------------------------------------------------
 */

export type ThreatClassification =
  | 'human'
  | 'trusted'
  | 'normal'
  | 'suspicious'
  | 'automated'
  | 'hostile';

/**
 * --------------------------------------------------------------------------
 * Threat Metadata
 * --------------------------------------------------------------------------
 */

export interface ThreatMetadata {
  analyzedAt: string;

  confidence: number;

  engine?: string;

  modelVersion?: string;

  correlationId?: string;

  additionalContext?: Record<string, unknown>;
}

/**
 * --------------------------------------------------------------------------
 * Unified Threat Analysis Result
 * --------------------------------------------------------------------------
 */

export interface ThreatAnalysisResult {
  /**
   * Numeric risk score.
   *
   * Expected range:
   * 0 → 100
   */
  score: number;

  /**
   * Security severity classification.
   */
  severity: ThreatSeverity;

  /**
   * Behavioral / operational classification.
   */
  classification: ThreatClassification;

  /**
   * Human-readable security indicators.
   */
  flags: string[];

  /**
   * Whether automated mitigation should trigger.
   */
  blocked: boolean;

  /**
   * Whether adaptive challenge escalation is required.
   */
  requiresChallenge?: boolean;

  /**
   * Optional geospatial anomaly indicator.
   */
  impossibleTravel?: boolean;

  /**
   * Optional estimated travel velocity.
   */
  estimatedVelocityKmh?: number;

  /**
   * Optional request timing delta.
   */
  timingDeltaMs?: number;

  /**
   * Additional structured metadata.
   */
  metadata: ThreatMetadata;
}

/**
 * --------------------------------------------------------------------------
 * Generic Threat Analyzer Contract
 * --------------------------------------------------------------------------
 */

export interface ThreatAnalyzer<
  TInput = unknown,
  TResult = ThreatAnalysisResult,
> {
  analyze(input: TInput): TResult;
}

/**
 * --------------------------------------------------------------------------
 * Threat Correlation Event
 * --------------------------------------------------------------------------
 */

export interface ThreatCorrelationEvent {
  eventId: string;

  userId?: string;

  ip: string;

  fingerprint?: string;

  source:
    | 'auth'
    | 'session'
    | 'api'
    | 'gateway'
    | 'ai-engine';

  severity: ThreatSeverity;

  classification: ThreatClassification;

  score: number;

  flags: string[];

  createdAt: string;
}

/**
 * --------------------------------------------------------------------------
 * Aggregated Threat Intelligence
 * --------------------------------------------------------------------------
 */

export interface AggregatedThreatResult {
  globalScore: number;

  severity: ThreatSeverity;

  blocked: boolean;

  analyzers: {
    anomaly?: ThreatAnalysisResult;

    behavior?: ThreatAnalysisResult;

    geo?: ThreatAnalysisResult;

    timing?: ThreatAnalysisResult;
  };

  correlation: {
    totalFlags: number;

    hostileSignals: number;

    confidence: number;
  };

  metadata: {
    generatedAt: string;

    engine: 'ASF-AI-Security';

    version: string;
  };
}