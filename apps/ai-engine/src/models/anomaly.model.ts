/* ============================================================
 * ASF AI Engine
 * Adaptive Behavioral Anomaly Model
 * File: anomaly.model.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines canonical anomaly intelligence structures
 * used by the ASF AI behavioral analysis engine.
 *
 * This model standardizes:
 * - anomaly scoring
 * - behavioral deviation telemetry
 * - signal confidence metrics
 * - ML inference outputs
 * - distributed threat intelligence
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Normalize anomaly intelligence
 * - Prevent inconsistent threat telemetry
 * - Support distributed AI inference
 * - Improve explainability pipelines
 * - Enable adaptive enforcement systems
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Immutable threat structures
 * - Strong typing guarantees
 * - AI/ML interoperability
 * - Low-latency serialization
 * - Explainable intelligence outputs
 *
 * ============================================================
 *
 * IMPORTANT:
 * Anomaly models represent probabilistic
 * behavioral intelligence only.
 *
 * NEVER:
 * - assume anomaly certainty
 * - hard-block on a single model result
 * - expose internal feature weights
 * - trust inference outputs blindly
 *
 * ============================================================
 */

/**
 * ============================================================
 * Threat Severity
 * ============================================================
 */

export enum ThreatSeverity {
  LOW = 'LOW',

  MEDIUM = 'MEDIUM',

  HIGH = 'HIGH',

  CRITICAL = 'CRITICAL',
}

/**
 * ============================================================
 * Threat Classification
 * ============================================================
 */

export enum ThreatType {
  UNKNOWN = 'UNKNOWN',

  BOT_ACTIVITY = 'BOT_ACTIVITY',

  REPLAY_ATTACK = 'REPLAY_ATTACK',

  SESSION_ANOMALY = 'SESSION_ANOMALY',

  BEHAVIORAL_DEVIATION = 'BEHAVIORAL_DEVIATION',

  AUTOMATED_ABUSE = 'AUTOMATED_ABUSE',

  DISTRIBUTED_FLOODING = 'DISTRIBUTED_FLOODING',
}

/**
 * ============================================================
 * Feature Vector
 * ============================================================
 *
 * Canonical normalized AI feature set
 * ============================================================
 */

export interface FeatureVector {
  requestVelocity: number;

  entropyScore: number;

  botProbability: number;

  replayRisk: number;

  sessionRisk: number;

  reputationRisk: number;

  geoRisk: number;

  networkRisk: number;

  behavioralDeviation: number;
}

/**
 * ============================================================
 * Inference Metadata
 * ============================================================
 */

export interface InferenceMetadata {
  model: string;

  modelVersion: string;

  inferenceTimeMs: number;

  generatedAt: number;

  correlationId?: string;
}

/**
 * ============================================================
 * Anomaly Indicators
 * ============================================================
 */

export interface AnomalyIndicators {
  suspiciousHeaders: boolean;

  abnormalVelocity: boolean;

  entropyCollapse: boolean;

  replayDetected: boolean;

  automationSignals: boolean;

  geoDeviation: boolean;

  sessionMutation: boolean;
}

/**
 * ============================================================
 * Behavioral Anomaly Result
 * ============================================================
 */

export interface BehavioralAnomaly {
  anomalyId: string;

  anomalyScore: number;

  confidence: number;

  severity: ThreatSeverity;

  threatType: ThreatType;

  trusted: boolean;

  blocked: boolean;

  indicators: string[];

  featureVector: FeatureVector;

  metadata: InferenceMetadata;

  telemetry?: Record<string, unknown>;
}

/**
 * ============================================================
 * AI Prediction Output
 * ============================================================
 */

export interface PredictionResult {
  predictionId: string;

  probability: number;

  label: ThreatType;

  confidence: number;

  explanation: string[];

  generatedAt: number;
}

/**
 * ============================================================
 * Training Sample
 * ============================================================
 */

export interface TrainingSample {
  id: string;

  features: FeatureVector;

  label: ThreatType;

  verified: boolean;

  timestamp: number;
}

/**
 * ============================================================
 * Behavioral Baseline
 * ============================================================
 */

export interface BehavioralBaseline {
  entityId: string;

  averageVelocity: number;

  averageEntropy: number;

  averageSessionRisk: number;

  trustScore: number;

  updatedAt: number;
}

/**
 * ============================================================
 * AI Risk Thresholds
 * ============================================================
 */

export const AI_RISK_THRESHOLDS = {
  SAFE: 0.25,

  MEDIUM: 0.5,

  HIGH: 0.75,

  CRITICAL: 0.9,
} as const;

/**
 * ============================================================
 * Anomaly Model Factory
 * ============================================================
 */

export class AnomalyModelFactory {
  /**
   * ==========================================================
   * Create Empty Feature Vector
   * ==========================================================
   */

  static emptyFeatureVector(): FeatureVector {
    return {
      requestVelocity: 0,

      entropyScore: 0,

      botProbability: 0,

      replayRisk: 0,

      sessionRisk: 0,

      reputationRisk: 0,

      geoRisk: 0,

      networkRisk: 0,

      behavioralDeviation: 0,
    };
  }

  /**
   * ==========================================================
   * Create Default Metadata
   * ==========================================================
   */

  static createMetadata(
    model: string,

    version: string,
  ): InferenceMetadata {
    return {
      model,

      modelVersion: version,

      inferenceTimeMs: 0,

      generatedAt: Date.now(),
    };
  }

  /**
   * ==========================================================
   * Create Default Anomaly Result
   * ==========================================================
   */

  static createDefault(): BehavioralAnomaly {
    return {
      anomalyId: crypto.randomUUID(),

      anomalyScore: 0,

      confidence: 0,

      severity: ThreatSeverity.LOW,

      threatType: ThreatType.UNKNOWN,

      trusted: true,

      blocked: false,

      indicators: [],

      featureVector: this.emptyFeatureVector(),

      metadata: this.createMetadata('ASF-AI', '1.0.0'),
    };
  }
}
