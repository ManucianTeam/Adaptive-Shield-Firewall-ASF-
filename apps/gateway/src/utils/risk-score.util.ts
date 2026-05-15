/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Adaptive Risk Score Utility
 * File: risk-score.util.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides centralized deterministic risk scoring
 * utilities for distributed security intelligence.
 *
 * This utility aggregates:
 * - anomaly signals
 * - reputation intelligence
 * - behavioral deviations
 * - session trust
 * - network heuristics
 * - replay indicators
 * - bot probabilities
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Standardize risk evaluation
 * - Reduce inconsistent threat scoring
 * - Support adaptive enforcement
 * - Improve telemetry correlation
 * - Enable future ML augmentation
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Stateless execution
 * - Deterministic scoring
 * - Lightweight calculations
 * - Explainable heuristics
 * - Low-latency evaluation
 *
 * ============================================================
 *
 * IMPORTANT:
 * Risk scores are probabilistic estimations.
 *
 * NEVER:
 * - treat scores as absolute truth
 * - hard-block on a single heuristic
 * - expose internal scoring weights
 * - assume trusted entities remain trusted
 *
 * ============================================================
 */

/**
 * ============================================================
 * Risk Factors
 * ============================================================
 */

export interface RiskFactors {
  anomalyScore?: number;

  reputationRisk?: number;

  sessionRisk?: number;

  botProbability?: number;

  replayRisk?: number;

  requestVelocity?: number;

  entropyScore?: number;

  geoRisk?: number;

  networkRisk?: number;
}

/**
 * ============================================================
 * Risk Classification
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
 * Risk Result
 * ============================================================
 */

export interface RiskResult {
  riskScore: number;

  riskLevel: RiskLevel;

  trusted: boolean;

  blocked: boolean;

  indicators: string[];
}

/**
 * ============================================================
 * Risk Score Utility
 * ============================================================
 */

export class RiskScoreUtil {
  /**
   * ==========================================================
   * Core Weighted Model
   * ==========================================================
   */

  private static readonly WEIGHTS = {
    anomaly: 0.25,

    reputation: 0.2,

    session: 0.1,

    bot: 0.15,

    replay: 0.1,

    velocity: 0.08,

    entropy: 0.05,

    geo: 0.04,

    network: 0.03,
  };

  /**
   * ==========================================================
   * Main Risk Calculation
   * ==========================================================
   */

  static calculate(factors: RiskFactors): RiskResult {
    const indicators: string[] = [];

    /**
     * ========================================================
     * Normalize Inputs
     * ========================================================
     */

    const anomaly = this.normalize(factors.anomalyScore);

    const reputation = this.normalize(factors.reputationRisk);

    const session = this.normalize(factors.sessionRisk);

    const bot = this.normalize(factors.botProbability);

    const replay = this.normalize(factors.replayRisk);

    const velocity = this.normalizeVelocity(factors.requestVelocity || 0);

    const entropy = this.normalizeEntropy(factors.entropyScore || 0);

    const geo = this.normalize(factors.geoRisk);

    const network = this.normalize(factors.networkRisk);

    /**
     * ========================================================
     * Weighted Deterministic Score
     * ========================================================
     */

    const riskScore =
      anomaly * this.WEIGHTS.anomaly +
      reputation * this.WEIGHTS.reputation +
      session * this.WEIGHTS.session +
      bot * this.WEIGHTS.bot +
      replay * this.WEIGHTS.replay +
      velocity * this.WEIGHTS.velocity +
      entropy * this.WEIGHTS.entropy +
      geo * this.WEIGHTS.geo +
      network * this.WEIGHTS.network;

    /**
     * ========================================================
     * Clamp Risk Score
     * ========================================================
     */

    const normalizedRisk = Math.max(0, Math.min(1, riskScore));

    /**
     * ========================================================
     * Signal Indicators
     * ========================================================
     */

    if (bot > 0.7) {
      indicators.push('HIGH_BOT_PROBABILITY');
    }

    if (replay > 0.7) {
      indicators.push('REPLAY_RISK_DETECTED');
    }

    if (velocity > 0.8) {
      indicators.push('ABNORMAL_REQUEST_VELOCITY');
    }

    if (entropy > 0.7) {
      indicators.push('LOW_ENTROPY_SIGNATURE');
    }

    if (geo > 0.6) {
      indicators.push('GEO_BEHAVIOR_ANOMALY');
    }

    if (network > 0.7) {
      indicators.push('SUSPICIOUS_NETWORK_ORIGIN');
    }

    /**
     * ========================================================
     * Risk Classification
     * ========================================================
     */

    let riskLevel = RiskLevel.SAFE;

    if (normalizedRisk >= 0.9) {
      riskLevel = RiskLevel.CRITICAL;
    } else if (normalizedRisk >= 0.75) {
      riskLevel = RiskLevel.HIGH;
    } else if (normalizedRisk >= 0.5) {
      riskLevel = RiskLevel.MEDIUM;
    } else if (normalizedRisk >= 0.25) {
      riskLevel = RiskLevel.LOW;
    }

    /**
     * ========================================================
     * Trust Decision
     * ========================================================
     */

    const trusted = normalizedRisk < 0.35;

    /**
     * ========================================================
     * Adaptive Block Threshold
     * ========================================================
     */

    const blocked = normalizedRisk >= 0.92;

    if (blocked) {
      indicators.push('ADAPTIVE_BLOCK_TRIGGERED');
    }

    /**
     * ========================================================
     * Final Result
     * ========================================================
     */

    return {
      riskScore: normalizedRisk,

      riskLevel,

      trusted,

      blocked,

      indicators,
    };
  }

  /**
   * ==========================================================
   * Normalize Generic Score
   * ==========================================================
   */

  private static normalize(value?: number): number {
    if (value === undefined || Number.isNaN(value)) {
      return 0;
    }

    return Math.max(0, Math.min(1, value));
  }

  /**
   * ==========================================================
   * Normalize Velocity
   * ==========================================================
   *
   * Production:
   * - rolling windows
   * - token buckets
   * - percentile normalization
   * ==========================================================
   */

  private static normalizeVelocity(velocity: number): number {
    return Math.min(1, velocity / 100);
  }

  /**
   * ==========================================================
   * Normalize Entropy
   * ==========================================================
   *
   * Lower entropy = higher risk
   * ==========================================================
   */

  private static normalizeEntropy(entropy: number): number {
    if (entropy <= 0) {
      return 1;
    }

    return Math.max(0, Math.min(1, 1 - entropy));
  }

  /**
   * ==========================================================
   * Merge Multiple Risk Results
   * ==========================================================
   */

  static merge(results: RiskResult[]): RiskResult {
    if (results.length === 0) {
      return {
        riskScore: 0,

        riskLevel: RiskLevel.SAFE,

        trusted: true,

        blocked: false,

        indicators: [],
      };
    }

    /**
     * ========================================================
     * Average Composite Risk
     * ========================================================
     */

    const riskScore =
      results.reduce((acc, curr) => acc + curr.riskScore, 0) / results.length;

    /**
     * ========================================================
     * Unique Indicators
     * ========================================================
     */

    const indicators = [...new Set(results.flatMap((r) => r.indicators))];

    /**
     * ========================================================
     * Final Aggregate
     * ========================================================
     */

    return this.calculate({
      anomalyScore: riskScore,
    });
  }
}
