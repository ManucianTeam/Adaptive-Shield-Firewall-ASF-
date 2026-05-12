import { Injectable, Logger } from '@nestjs/common';

export interface AnomalyAnalysisInput {
  ip: string;
  userId?: string;
  userAgent?: string;
  fingerprint?: string;

  requestCount: number;
  failedAttempts: number;

  geoDistanceKm?: number;
  velocityKmPerHour?: number;

  requestIntervalMs?: number;

  knownDevice?: boolean;
  knownIp?: boolean;

  sessionAgeSeconds?: number;
}

export interface AnomalyAnalysisResult {
  score: number;
  risk: 'low' | 'medium' | 'high' | 'critical';

  flags: string[];

  blocked: boolean;

  metadata: {
    normalizedScore: number;
    evaluatedAt: string;
  };
}

/**
 * ============================================================================
 * ASF AI Security — Anomaly Analyzer
 * ============================================================================
 *
 * Behavioral anomaly detection engine for authentication and request analysis.
 *
 * This analyzer evaluates:
 *
 *  - suspicious request frequency
 *  - credential abuse patterns
 *  - impossible travel events
 *  - abnormal session velocity
 *  - unknown device fingerprints
 *  - session irregularities
 *
 * The scoring model is intentionally lightweight and deterministic,
 * enabling low-latency execution inside the authentication pipeline.
 *
 * Future versions may replace this rule-based engine with:
 *
 *  - statistical baselines
 *  - online learning
 *  - graph-based trust correlation
 *  - sequence anomaly transformers
 *  - distributed reputation federation
 *
 * ============================================================================
 */

@Injectable()
export class AnomalyAnalyzer {
  private readonly logger = new Logger(
    AnomalyAnalyzer.name,
  );

  /**
   * --------------------------------------------------------------------------
   * Main Analysis Entry
   * --------------------------------------------------------------------------
   */

  analyze(
    input: AnomalyAnalysisInput,
  ): AnomalyAnalysisResult {
    let score = 0;

    const flags: string[] = [];

    // ------------------------------------------------------------------------
    // Failed Authentication Analysis
    // ------------------------------------------------------------------------

    if (input.failedAttempts >= 3) {
      score += 15;

      flags.push(
        'multiple_failed_authentication_attempts',
      );
    }

    if (input.failedAttempts >= 8) {
      score += 25;

      flags.push(
        'credential_abuse_pattern_detected',
      );
    }

    // ------------------------------------------------------------------------
    // Request Flood / Automation Detection
    // ------------------------------------------------------------------------

    if (input.requestCount > 120) {
      score += 20;

      flags.push(
        'abnormal_request_frequency',
      );
    }

    if (input.requestIntervalMs !== undefined) {
      if (input.requestIntervalMs < 150) {
        score += 18;

        flags.push(
          'non_human_request_timing',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Geo & Velocity Analysis
    // ------------------------------------------------------------------------

    if (
      input.geoDistanceKm !== undefined &&
      input.velocityKmPerHour !== undefined
    ) {
      if (
        input.geoDistanceKm > 500 &&
        input.velocityKmPerHour > 900
      ) {
        score += 40;

        flags.push(
          'impossible_travel_detected',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Device Trust Analysis
    // ------------------------------------------------------------------------

    if (input.knownDevice === false) {
      score += 10;

      flags.push(
        'unknown_device_fingerprint',
      );
    }

    if (input.knownIp === false) {
      score += 8;

      flags.push(
        'unknown_ip_origin',
      );
    }

    // ------------------------------------------------------------------------
    // Session Irregularity Analysis
    // ------------------------------------------------------------------------

    if (
      input.sessionAgeSeconds !== undefined &&
      input.sessionAgeSeconds < 10
    ) {
      score += 10;

      flags.push(
        'new_session_high_activity',
      );
    }

    // ------------------------------------------------------------------------
    // Score Normalization
    // ------------------------------------------------------------------------

    const normalizedScore = Math.min(
      100,
      Math.max(0, score),
    );

    // ------------------------------------------------------------------------
    // Risk Classification
    // ------------------------------------------------------------------------

    let risk:
      | 'low'
      | 'medium'
      | 'high'
      | 'critical' = 'low';

    if (normalizedScore >= 75) {
      risk = 'critical';
    } else if (normalizedScore >= 50) {
      risk = 'high';
    } else if (normalizedScore >= 25) {
      risk = 'medium';
    }

    // ------------------------------------------------------------------------
    // Automated Blocking Decision
    // ------------------------------------------------------------------------

    const blocked = normalizedScore >= 80;

    // ------------------------------------------------------------------------
    // Structured Security Logging
    // ------------------------------------------------------------------------

    this.logger.warn({
      message: 'Anomaly analysis completed',

      userId: input.userId,

      ip: input.ip,

      score: normalizedScore,

      risk,

      blocked,

      flags,
    });

    return {
      score: normalizedScore,

      risk,

      flags,

      blocked,

      metadata: {
        normalizedScore,
        evaluatedAt: new Date().toISOString(),
      },
    };
  }
}