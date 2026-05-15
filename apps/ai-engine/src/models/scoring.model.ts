/* ============================================================
 * ASF AI Engine
 * Adaptive Threat Scoring Model
 * File: scoring.model.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines canonical adaptive threat scoring
 * structures used by the ASF intelligence engine.
 *
 * This model standardizes:
 * - deterministic risk scoring
 * - weighted signal aggregation
 * - trust evaluation
 * - enforcement recommendations
 * - explainable threat intelligence
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Centralize risk classification
 * - Normalize distributed scoring logic
 * - Improve explainability pipelines
 * - Reduce inconsistent enforcement
 * - Support future ML augmentation
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Immutable scoring structures
 * - Explainable weighted models
 * - Low-latency serialization
 * - Distributed-system compatibility
 * - AI-ready intelligence outputs
 *
 * ============================================================
 *
 * IMPORTANT:
 * Threat scores are probabilistic estimations.
 *
 * NEVER:
 * - assume scoring certainty
 * - expose internal secret heuristics
 * - hard-block on isolated weak signals
 * - trust static risk baselines
 *
 * ============================================================
 */

/**
 * ============================================================
 * Risk Level
 * ============================================================
 */

export enum RiskLevel {
  SAFE = 'SAFE',

  LOW = 'LOW',

  MEDIUM = 'MEDIUM',

  HIGH = 'HIGH',

  CRITICAL = 'CRITICAL',
}

/**
 * ============================================================
 * Threat Category
 * ============================================================
 */

export enum ThreatCategory {
  UNKNOWN = 'UNKNOWN',

  AUTOMATION = 'AUTOMATION',

  REPLAY = 'REPLAY',

  BEHAVIORAL = 'BEHAVIORAL',

  DISTRIBUTED_ATTACK = 'DISTRIBUTED_ATTACK',

  SESSION_ABUSE = 'SESSION_ABUSE',

  NETWORK_ABUSE = 'NETWORK_ABUSE',
}

/**
 * ============================================================
 * Weighted Signal
 * ============================================================
 */

export interface WeightedSignal {
  name: string;

  value: number;

  weight: number;

  contribution: number;

  trusted: boolean;
}

/**
 * ============================================================
 * Scoring Vector
 * ============================================================
 */

export interface ScoringVector {
  anomalyScore: number;

  reputationScore: number;

  sessionRisk: number;

  replayRisk: number;

  botProbability: number;

  behavioralDeviation: number;

  networkRisk: number;

  geoRisk: number;

  concurrencyRisk: number;
}

/**
 * ============================================================
 * Enforcement Recommendation
 * ============================================================
 */

export interface EnforcementRecommendation {
  block: boolean;

  challenge: boolean;

  throttle: boolean;

  monitor: boolean;

  quarantine: boolean;

  reason: string[];
}

/**
 * ============================================================
 * Scoring Metadata
 * ============================================================
 */

export interface ScoringMetadata {
  scoringId: string;

  engine: string;

  engineVersion: string;

  generatedAt: number;

  evaluationTimeMs: number;

  correlationId?: string;
}

/**
 * ============================================================
 * Threat Score Result
 * ============================================================
 */

export interface ThreatScore {
  score: number;

  confidence: number;

  level: RiskLevel;

  category: ThreatCategory;

  trusted: boolean;

  blocked: boolean;

  indicators: string[];

  signals: WeightedSignal[];

  vector: ScoringVector;

  enforcement: EnforcementRecommendation;

  metadata: ScoringMetadata;
}

/**
 * ============================================================
 * Adaptive Score Thresholds
 * ============================================================
 */

export const SCORE_THRESHOLDS = {
  SAFE: 0.25,

  LOW: 0.45,

  MEDIUM: 0.65,

  HIGH: 0.8,

  CRITICAL: 0.92,
} as const;

/**
 * ============================================================
 * Default Signal Weights
 * ============================================================
 */

export const DEFAULT_SIGNAL_WEIGHTS = {
  anomalyScore: 0.24,

  reputationScore: 0.18,

  sessionRisk: 0.1,

  replayRisk: 0.12,

  botProbability: 0.14,

  behavioralDeviation: 0.1,

  networkRisk: 0.05,

  geoRisk: 0.03,

  concurrencyRisk: 0.04,
} as const;

/**
 * ============================================================
 * Threat Scoring Factory
 * ============================================================
 */

export class ScoringModelFactory {
  /**
   * ==========================================================
   * Empty Scoring Vector
   * ==========================================================
   */

  static emptyVector(): ScoringVector {
    return {
      anomalyScore: 0,

      reputationScore: 0,

      sessionRisk: 0,

      replayRisk: 0,

      botProbability: 0,

      behavioralDeviation: 0,

      networkRisk: 0,

      geoRisk: 0,

      concurrencyRisk: 0,
    };
  }

  /**
   * ==========================================================
   * Default Enforcement
   * ==========================================================
   */

  static defaultEnforcement(): EnforcementRecommendation {
    return {
      block: false,

      challenge: false,

      throttle: false,

      monitor: true,

      quarantine: false,

      reason: [],
    };
  }

  /**
   * ==========================================================
   * Metadata Factory
   * ==========================================================
   */

  static createMetadata(
    engine = 'ASF-SCORING',

    version = '1.0.0',
  ): ScoringMetadata {
    return {
      scoringId: crypto.randomUUID(),

      engine,

      engineVersion: version,

      generatedAt: Date.now(),

      evaluationTimeMs: 0,
    };
  }

  /**
   * ==========================================================
   * Risk Level Resolver
   * ==========================================================
   */

  static resolveRiskLevel(score: number): RiskLevel {
    if (score >= SCORE_THRESHOLDS.CRITICAL) {
      return RiskLevel.CRITICAL;
    }

    if (score >= SCORE_THRESHOLDS.HIGH) {
      return RiskLevel.HIGH;
    }

    if (score >= SCORE_THRESHOLDS.MEDIUM) {
      return RiskLevel.MEDIUM;
    }

    if (score >= SCORE_THRESHOLDS.LOW) {
      return RiskLevel.LOW;
    }

    return RiskLevel.SAFE;
  }

  /**
   * ==========================================================
   * Threat Category Resolver
   * ==========================================================
   */

  static resolveCategory(vector: ScoringVector): ThreatCategory {
    if (vector.replayRisk > 0.8) {
      return ThreatCategory.REPLAY;
    }

    if (vector.botProbability > 0.75) {
      return ThreatCategory.AUTOMATION;
    }

    if (vector.behavioralDeviation > 0.7) {
      return ThreatCategory.BEHAVIORAL;
    }

    if (vector.networkRisk > 0.75) {
      return ThreatCategory.NETWORK_ABUSE;
    }

    if (vector.concurrencyRisk > 0.7) {
      return ThreatCategory.DISTRIBUTED_ATTACK;
    }

    if (vector.sessionRisk > 0.7) {
      return ThreatCategory.SESSION_ABUSE;
    }

    return ThreatCategory.UNKNOWN;
  }

  /**
   * ==========================================================
   * Default Threat Score
   * ==========================================================
   */

  static createDefault(): ThreatScore {
    return {
      score: 0,

      confidence: 0,

      level: RiskLevel.SAFE,

      category: ThreatCategory.UNKNOWN,

      trusted: true,

      blocked: false,

      indicators: [],

      signals: [],

      vector: this.emptyVector(),

      enforcement: this.defaultEnforcement(),

      metadata: this.createMetadata(),
    };
  }
}
