/* ============================================================
 * ASF AI Engine
 * Behavioral Intelligence Model
 * File: behavior.model.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines canonical behavioral intelligence structures
 * used for adaptive user profiling, session analytics,
 * anomaly correlation, and threat prediction.
 *
 * This model standardizes:
 * - behavioral telemetry
 * - interaction profiling
 * - request pattern analysis
 * - trust evolution tracking
 * - AI-compatible feature pipelines
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Detect behavioral deviations
 * - Build adaptive trust baselines
 * - Improve anomaly explainability
 * - Reduce false-positive enforcement
 * - Support distributed AI inference
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Immutable behavioral structures
 * - Explainable telemetry
 * - Lightweight serialization
 * - Deterministic schemas
 * - ML-ready feature compatibility
 *
 * ============================================================
 *
 * IMPORTANT:
 * Behavioral intelligence is probabilistic.
 *
 * NEVER:
 * - assume human behavior consistency
 * - trust static interaction baselines
 * - expose raw profiling internals
 * - treat behavioral confidence as certainty
 *
 * ============================================================
 */

/**
 * ============================================================
 * Behavior Classification
 * ============================================================
 */

export enum BehaviorType {
  NORMAL = 'NORMAL',

  SUSPICIOUS = 'SUSPICIOUS',

  AUTOMATED = 'AUTOMATED',

  MALICIOUS = 'MALICIOUS',

  UNKNOWN = 'UNKNOWN',
}

/**
 * ============================================================
 * Interaction Pattern
 * ============================================================
 */

export enum InteractionPattern {
  HUMAN = 'HUMAN',

  BOT = 'BOT',

  SCRIPTED = 'SCRIPTED',

  BURST_TRAFFIC = 'BURST_TRAFFIC',

  DISTRIBUTED = 'DISTRIBUTED',
}

/**
 * ============================================================
 * Behavioral Metrics
 * ============================================================
 */

export interface BehavioralMetrics {
  requestVelocity: number;

  averageRequestInterval: number;

  entropyScore: number;

  navigationDepth: number;

  interactionScore: number;

  mutationScore: number;

  sessionStability: number;

  behavioralDeviation: number;
}

/**
 * ============================================================
 * Behavioral Timing
 * ============================================================
 */

export interface BehavioralTiming {
  firstSeenAt: number;

  lastSeenAt: number;

  sessionDurationMs: number;

  activeWindowMs: number;

  averageThinkTimeMs: number;
}

/**
 * ============================================================
 * Navigation Profile
 * ============================================================
 */

export interface NavigationProfile {
  entryPath: string;

  lastPath: string;

  traversalDepth: number;

  uniqueEndpoints: number;

  suspiciousRoutes: string[];

  repeatedPatterns: boolean;
}

/**
 * ============================================================
 * Input Behavior
 * ============================================================
 */

export interface InputBehavior {
  mouseActivityDetected: boolean;

  keyboardActivityDetected: boolean;

  touchActivityDetected: boolean;

  interactionConsistency: number;

  syntheticInteractionProbability: number;
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

  averageInteractionScore: number;

  averageSessionDuration: number;

  trustScore: number;

  updatedAt: number;
}

/**
 * ============================================================
 * Behavioral Telemetry
 * ============================================================
 */

export interface BehavioralTelemetry {
  telemetryId: string;

  source: string;

  correlationId?: string;

  generatedAt: number;

  metadata?: Record<string, unknown>;
}

/**
 * ============================================================
 * Behavioral Profile
 * ============================================================
 */

export interface BehavioralProfile {
  profileId: string;

  entityId: string;

  type: BehaviorType;

  interactionPattern: InteractionPattern;

  trustScore: number;

  confidence: number;

  metrics: BehavioralMetrics;

  timing: BehavioralTiming;

  navigation: NavigationProfile;

  input: InputBehavior;

  indicators: string[];

  telemetry: BehavioralTelemetry;
}

/**
 * ============================================================
 * Behavioral Prediction
 * ============================================================
 */

export interface BehavioralPrediction {
  predictionId: string;

  predictedType: BehaviorType;

  confidence: number;

  riskScore: number;

  explanation: string[];

  generatedAt: number;
}

/**
 * ============================================================
 * Behavior Thresholds
 * ============================================================
 */

export const BEHAVIOR_THRESHOLDS = {
  LOW_RISK: 0.25,

  MEDIUM_RISK: 0.5,

  HIGH_RISK: 0.75,

  CRITICAL_RISK: 0.9,
} as const;

/**
 * ============================================================
 * Behavioral Model Factory
 * ============================================================
 */

export class BehaviorModelFactory {
  /**
   * ==========================================================
   * Create Empty Metrics
   * ==========================================================
   */

  static emptyMetrics(): BehavioralMetrics {
    return {
      requestVelocity: 0,

      averageRequestInterval: 0,

      entropyScore: 0,

      navigationDepth: 0,

      interactionScore: 0,

      mutationScore: 0,

      sessionStability: 1,

      behavioralDeviation: 0,
    };
  }

  /**
   * ==========================================================
   * Create Empty Timing
   * ==========================================================
   */

  static emptyTiming(): BehavioralTiming {
    const now = Date.now();

    return {
      firstSeenAt: now,

      lastSeenAt: now,

      sessionDurationMs: 0,

      activeWindowMs: 0,

      averageThinkTimeMs: 0,
    };
  }

  /**
   * ==========================================================
   * Create Default Navigation
   * ==========================================================
   */

  static emptyNavigation(): NavigationProfile {
    return {
      entryPath: '/',

      lastPath: '/',

      traversalDepth: 0,

      uniqueEndpoints: 0,

      suspiciousRoutes: [],

      repeatedPatterns: false,
    };
  }

  /**
   * ==========================================================
   * Create Default Input Profile
   * ==========================================================
   */

  static emptyInput(): InputBehavior {
    return {
      mouseActivityDetected: false,

      keyboardActivityDetected: false,

      touchActivityDetected: false,

      interactionConsistency: 0,

      syntheticInteractionProbability: 0,
    };
  }

  /**
   * ==========================================================
   * Create Telemetry Metadata
   * ==========================================================
   */

  static createTelemetry(source: string): BehavioralTelemetry {
    return {
      telemetryId: crypto.randomUUID(),

      source,

      generatedAt: Date.now(),
    };
  }

  /**
   * ==========================================================
   * Create Default Profile
   * ==========================================================
   */

  static createDefault(entityId: string): BehavioralProfile {
    return {
      profileId: crypto.randomUUID(),

      entityId,

      type: BehaviorType.UNKNOWN,

      interactionPattern: InteractionPattern.HUMAN,

      trustScore: 1,

      confidence: 0,

      metrics: this.emptyMetrics(),

      timing: this.emptyTiming(),

      navigation: this.emptyNavigation(),

      input: this.emptyInput(),

      indicators: [],

      telemetry: this.createTelemetry('ASF-AI'),
    };
  }
}
