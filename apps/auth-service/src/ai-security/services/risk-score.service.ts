// apps/auth-service/src/ai-security/services/risk-score.service.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  AggregatedThreatResult,
  ThreatAnalysisResult,
  ThreatClassification,
  ThreatSeverity,
} from '../interfaces/threat-analysis.interface';

/**
 * ============================================================================
 * ASF AI Security — Risk Score Service
 * ============================================================================
 *
 * Centralized adaptive threat aggregation engine responsible for:
 *
 *  - multi-analyzer correlation
 *  - distributed risk fusion
 *  - weighted threat normalization
 *  - mitigation escalation
 *  - adaptive trust scoring
 *  - hostile signal amplification
 *
 * This service consumes outputs from:
 *
 *  - anomaly analyzers
 *  - behavioral analyzers
 *  - geospatial analyzers
 *  - timing analyzers
 *
 * and produces a unified security intelligence decision suitable for:
 *
 *  - authentication pipelines
 *  - API gateways
 *  - session orchestration
 *  - adaptive MFA systems
 *  - distributed firewall enforcement
 *
 * The aggregation model is intentionally deterministic and lightweight
 * to maintain extremely low execution latency in high-throughput systems.
 *
 * Future versions may integrate:
 *
 *  - Bayesian threat fusion
 *  - graph-based trust propagation
 *  - reinforcement learning
 *  - federated threat intelligence
 *  - distributed behavioral embeddings
 *
 * ============================================================================
 */

@Injectable()
export class RiskScoreService {
  private readonly logger = new Logger(
    RiskScoreService.name,
  );

  /**
   * --------------------------------------------------------------------------
   * Analyzer Weight Configuration
   * --------------------------------------------------------------------------
   */

  private readonly weights = {
    anomaly: 0.35,
    behavior: 0.25,
    geo: 0.20,
    timing: 0.20,
  };

  /**
   * --------------------------------------------------------------------------
   * Aggregate Threat Intelligence
   * --------------------------------------------------------------------------
   */

  aggregate(input: {
    anomaly?: ThreatAnalysisResult;
    behavior?: ThreatAnalysisResult;
    geo?: ThreatAnalysisResult;
    timing?: ThreatAnalysisResult;
  }): AggregatedThreatResult {
    const scores: number[] = [];

    const flags: string[] = [];

    let hostileSignals = 0;

    // ------------------------------------------------------------------------
    // Weighted Threat Aggregation
    // ------------------------------------------------------------------------

    if (input.anomaly) {
      scores.push(
        input.anomaly.score *
          this.weights.anomaly,
      );

      flags.push(...input.anomaly.flags);

      hostileSignals +=
        this.calculateHostileSignals(
          input.anomaly,
        );
    }

    if (input.behavior) {
      scores.push(
        input.behavior.score *
          this.weights.behavior,
      );

      flags.push(...input.behavior.flags);

      hostileSignals +=
        this.calculateHostileSignals(
          input.behavior,
        );
    }

    if (input.geo) {
      scores.push(
        input.geo.score *
          this.weights.geo,
      );

      flags.push(...input.geo.flags);

      hostileSignals +=
        this.calculateHostileSignals(
          input.geo,
        );
    }

    if (input.timing) {
      scores.push(
        input.timing.score *
          this.weights.timing,
      );

      flags.push(...input.timing.flags);

      hostileSignals +=
        this.calculateHostileSignals(
          input.timing,
        );
    }

    // ------------------------------------------------------------------------
    // Global Score Calculation
    // ------------------------------------------------------------------------

    let globalScore = Math.round(
      scores.reduce(
        (acc, value) => acc + value,
        0,
      ),
    );

    // ------------------------------------------------------------------------
    // Hostile Signal Amplification
    // ------------------------------------------------------------------------

    if (hostileSignals >= 2) {
      globalScore += 10;
    }

    if (hostileSignals >= 4) {
      globalScore += 20;
    }

    // ------------------------------------------------------------------------
    // Impossible Travel Escalation
    // ------------------------------------------------------------------------

    if (input.geo?.impossibleTravel) {
      globalScore += 15;
    }

    // ------------------------------------------------------------------------
    // Automated Timing Escalation
    // ------------------------------------------------------------------------

    if (
      input.timing?.classification ===
      'hostile'
    ) {
      globalScore += 20;
    }

    // ------------------------------------------------------------------------
    // Score Normalization
    // ------------------------------------------------------------------------

    globalScore = Math.min(
      100,
      Math.max(0, globalScore),
    );

    // ------------------------------------------------------------------------
    // Severity Classification
    // ------------------------------------------------------------------------

    const severity =
      this.resolveSeverity(globalScore);

    // ------------------------------------------------------------------------
    // Blocking Decision
    // ------------------------------------------------------------------------

    const blocked =
      severity === 'critical';

    // ------------------------------------------------------------------------
    // Confidence Estimation
    // ------------------------------------------------------------------------

    const confidence =
      this.calculateConfidence(
        globalScore,
        hostileSignals,
      );

    // ------------------------------------------------------------------------
    // Structured Security Telemetry
    // ------------------------------------------------------------------------

    this.logger.warn({
      message:
        'Threat aggregation completed',

      globalScore,

      severity,

      blocked,

      hostileSignals,

      totalFlags: flags.length,
    });

    return {
      globalScore,

      severity,

      blocked,

      analyzers: {
        anomaly: input.anomaly,
        behavior: input.behavior,
        geo: input.geo,
        timing: input.timing,
      },

      correlation: {
        totalFlags: flags.length,

        hostileSignals,

        confidence,
      },

      metadata: {
        generatedAt:
          new Date().toISOString(),

        engine: 'ASF-AI-Security',

        version: '1.0.0',
      },
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Threat Severity Resolver
   * --------------------------------------------------------------------------
   */

  private resolveSeverity(
    score: number,
  ): ThreatSeverity {
    if (score >= 85) {
      return 'critical';
    }

    if (score >= 60) {
      return 'high';
    }

    if (score >= 30) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * --------------------------------------------------------------------------
   * Hostile Signal Correlation
   * --------------------------------------------------------------------------
   */

  private calculateHostileSignals(
    result: ThreatAnalysisResult,
  ): number {
    let count = 0;

    const hostileFlags = [
      'impossible_travel_detected',
      'tor_exit_node_detected',
      'automation_speed_signature',
      'deterministic_timing_signature',
      'credential_abuse_pattern_detected',
      'extreme_request_flood_pattern',
      'non_human_request_frequency',
      'inhuman_typing_latency',
    ];

    for (const flag of result.flags) {
      if (hostileFlags.includes(flag)) {
        count++;
      }
    }

    if (
      result.classification ===
        'hostile' ||
      result.classification ===
        'automated'
    ) {
      count += 2;
    }

    return count;
  }

  /**
   * --------------------------------------------------------------------------
   * Confidence Estimation
   * --------------------------------------------------------------------------
   */

  private calculateConfidence(
    score: number,
    hostileSignals: number,
  ): number {
    let confidence = score / 100;

    confidence += hostileSignals * 0.05;

    return Math.min(
      1,
      Number(confidence.toFixed(2)),
    );
  }

  /**
   * --------------------------------------------------------------------------
   * Trust Classification Resolver
   * --------------------------------------------------------------------------
   */

  resolveClassification(
    score: number,
  ): ThreatClassification {
    if (score >= 90) {
      return 'hostile';
    }

    if (score >= 65) {
      return 'automated';
    }

    if (score >= 40) {
      return 'suspicious';
    }

    if (score >= 20) {
      return 'normal';
    }

    return 'trusted';
  }
}