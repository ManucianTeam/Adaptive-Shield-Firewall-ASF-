/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Reputation Intelligence Service
 * File: reputation.service.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides adaptive reputation analysis and trust
 * evaluation for clients, sessions, fingerprints,
 * IP addresses, and behavioral entities.
 *
 * This engine aggregates:
 * - historical behavior
 * - threat telemetry
 * - abuse frequency
 * - bot probability
 * - session stability
 * - network intelligence
 * - enforcement history
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Establish trust confidence levels
 * - Detect recurring malicious entities
 * - Reduce false-positive enforcement
 * - Enable adaptive mitigation policies
 * - Support zero-trust architectures
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Deterministic scoring
 * - Distributed cache compatibility
 * - Lightweight signal evaluation
 * - Temporal decay support
 * - Future ML extensibility
 *
 * ============================================================
 *
 * IMPORTANT:
 * Reputation is probabilistic intelligence only.
 *
 * NEVER:
 * - permanently trust entities
 * - hard block solely from reputation
 * - expose scoring internals externally
 * - ignore temporal behavior changes
 *
 * ============================================================
 */

import { Injectable, Logger } from '@nestjs/common';

import { createHash } from 'crypto';

import Redis from 'ioredis';

import { RequestContext } from '../interfaces/request-context.interface';

import { ThreatSeverity, ThreatType } from '../interfaces/threat.interface';

/**
 * ============================================================
 * Reputation Result
 * ============================================================
 */

export interface ReputationResult {
  reputationId: string;

  trustScore: number;

  reputationLevel: ReputationLevel;

  threatType: ThreatType;

  severity: ThreatSeverity;

  indicators: string[];

  enforcementRecommended: boolean;
}

/**
 * ============================================================
 * Reputation Levels
 * ============================================================
 */

export enum ReputationLevel {
  TRUSTED = 'TRUSTED',

  NORMAL = 'NORMAL',

  SUSPICIOUS = 'SUSPICIOUS',

  MALICIOUS = 'MALICIOUS',
}

/**
 * ============================================================
 * Reputation Service
 * ============================================================
 */

@Injectable()
export class ReputationService {
  /**
   * ==========================================================
   * Logger
   * ==========================================================
   */

  private readonly logger = new Logger(ReputationService.name);

  /**
   * ==========================================================
   * Redis Client
   * ==========================================================
   */

  private readonly redis: Redis;

  /**
   * ==========================================================
   * Reputation Configuration
   * ==========================================================
   */

  private readonly DEFAULT_REPUTATION = 0.5;

  private readonly REPUTATION_TTL = 60 * 60 * 24 * 14; // 14 days

  /**
   * ==========================================================
   * Constructor
   * ==========================================================
   */

  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',

      port: Number(process.env.REDIS_PORT || 6379),

      password: process.env.REDIS_PASSWORD,

      lazyConnect: true,
    });

    this.redis.on('connect', () => {
      this.logger.log('🧠 Reputation engine connected');
    });

    this.redis.on('error', (error) => {
      this.logger.error('Redis reputation error', error);
    });
  }

  /**
   * ==========================================================
   * Evaluate Reputation
   * ==========================================================
   */

  async evaluate(context: RequestContext): Promise<ReputationResult> {
    const fingerprint = context.fingerprint;

    /**
     * ========================================================
     * Missing Fingerprint
     * ========================================================
     */

    if (!fingerprint) {
      return {
        reputationId: 'unknown',

        trustScore: 0.35,

        reputationLevel: ReputationLevel.SUSPICIOUS,

        threatType: ThreatType.UNKNOWN,

        severity: ThreatSeverity.LOW,

        indicators: ['FINGERPRINT_UNAVAILABLE'],

        enforcementRecommended: false,
      };
    }

    /**
     * ========================================================
     * Identity Key
     * ========================================================
     */

    const reputationId = this.generateReputationId(
      fingerprint.ipAddress || context.ip || 'unknown',
    );

    /**
     * ========================================================
     * Historical Reputation
     * ========================================================
     */

    const historicalScore = await this.getHistoricalReputation(reputationId);

    /**
     * ========================================================
     * Signal Extraction
     * ========================================================
     */

    const botProbability = fingerprint.botProbability || 0;

    const replayRisk = fingerprint.replayRisk || 0;

    const velocity = fingerprint.behavior?.requestVelocity || 0;

    const entropy = fingerprint.entropy?.compositeEntropy || 0;

    const datacenterTraffic = fingerprint.network?.isDatacenter;

    /**
     * ========================================================
     * Deterministic Trust Computation
     * ========================================================
     */

    let trustScore = historicalScore;

    const indicators: string[] = [];

    /**
     * ========================================================
     * Bot Probability Penalty
     * ========================================================
     */

    if (botProbability > 0.75) {
      trustScore -= 0.25;

      indicators.push('HIGH_BOT_PROBABILITY');
    }

    /**
     * ========================================================
     * Replay Risk Penalty
     * ========================================================
     */

    if (replayRisk > 0.7) {
      trustScore -= 0.2;

      indicators.push('REPLAY_BEHAVIOR_DETECTED');
    }

    /**
     * ========================================================
     * Velocity Abuse Detection
     * ========================================================
     */

    if (velocity > 30) {
      trustScore -= 0.2;

      indicators.push('ABNORMAL_REQUEST_VELOCITY');
    }

    /**
     * ========================================================
     * Low Entropy Heuristic
     * ========================================================
     */

    if (entropy < 2.5) {
      trustScore -= 0.1;

      indicators.push('LOW_BEHAVIORAL_ENTROPY');
    }

    /**
     * ========================================================
     * Datacenter Traffic Heuristic
     * ========================================================
     */

    if (datacenterTraffic) {
      trustScore -= 0.1;

      indicators.push('DATACENTER_ORIGIN_TRAFFIC');
    }

    /**
     * ========================================================
     * Clamp Trust Score
     * ========================================================
     */

    trustScore = Math.max(0, Math.min(1, trustScore));

    /**
     * ========================================================
     * Reputation Classification
     * ========================================================
     */

    let reputationLevel = ReputationLevel.NORMAL;

    let threatType = ThreatType.UNKNOWN;

    let severity = ThreatSeverity.LOW;

    if (trustScore <= 0.2) {
      reputationLevel = ReputationLevel.MALICIOUS;

      threatType = ThreatType.AUTOMATED_ABUSE;

      severity = ThreatSeverity.CRITICAL;
    } else if (trustScore <= 0.45) {
      reputationLevel = ReputationLevel.SUSPICIOUS;

      threatType = ThreatType.BEHAVIORAL_DEVIATION;

      severity = ThreatSeverity.MEDIUM;
    } else if (trustScore >= 0.85) {
      reputationLevel = ReputationLevel.TRUSTED;
    }

    /**
     * ========================================================
     * Store Updated Reputation
     * ========================================================
     */

    await this.storeReputation(reputationId, trustScore);

    /**
     * ========================================================
     * Enforcement Recommendation
     * ========================================================
     */

    const enforcementRecommended =
      reputationLevel === ReputationLevel.MALICIOUS || trustScore < 0.3;

    /**
     * ========================================================
     * Telemetry Logging
     * ========================================================
     */

    this.logger.warn({
      event: 'REPUTATION_EVALUATION_COMPLETE',

      reputationId,

      trustScore,

      reputationLevel,

      threatType,

      severity,

      indicators,

      enforcementRecommended,

      timestamp: Date.now(),
    });

    /**
     * ========================================================
     * Result
     * ========================================================
     */

    return {
      reputationId,

      trustScore,

      reputationLevel,

      threatType,

      severity,

      indicators,

      enforcementRecommended,
    };
  }

  /**
   * ==========================================================
   * Historical Reputation Lookup
   * ==========================================================
   */

  private async getHistoricalReputation(reputationId: string): Promise<number> {
    const key = this.buildReputationKey(reputationId);

    const cached = await this.redis.get(key);

    if (!cached) {
      return this.DEFAULT_REPUTATION;
    }

    return Number(cached);
  }

  /**
   * ==========================================================
   * Store Reputation
   * ==========================================================
   */

  private async storeReputation(
    reputationId: string,

    score: number,
  ): Promise<void> {
    const key = this.buildReputationKey(reputationId);

    await this.redis.set(key, score.toFixed(4), 'EX', this.REPUTATION_TTL);
  }

  /**
   * ==========================================================
   * Generate Reputation ID
   * ==========================================================
   */

  private generateReputationId(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  /**
   * ==========================================================
   * Reputation Key Builder
   * ==========================================================
   */

  private buildReputationKey(reputationId: string): string {
    return `asf:reputation:${reputationId}`;
  }
}
