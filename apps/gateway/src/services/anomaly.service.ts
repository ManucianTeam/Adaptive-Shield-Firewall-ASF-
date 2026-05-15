/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Behavioral Anomaly Detection Service
 * File: anomaly.service.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides centralized anomaly scoring and behavioral
 * deviation analysis for incoming requests using
 * lightweight statistical heuristics and fingerprint signals.
 *
 * SECURITY OBJECTIVES:
 * - Detect abnormal traffic behavior patterns
 * - Identify deviation from baseline user behavior
 * - Support adaptive risk scoring engine
 * - Correlate multi-signal threat indicators
 * - Feed mitigation and enforcement layers
 *
 * DESIGN PRINCIPLES:
 * - Stateless computation (service-level purity)
 * - Deterministic scoring model
 * - Lightweight feature evaluation
 * - Pluggable future AI integration
 * - Low-latency execution
 *
 * IMPORTANT:
 * This service provides probabilistic scoring only.
 *
 * NEVER:
 * - treat anomaly score as absolute truth
 * - block users based on single metric
 * - expose internal scoring weights externally
 *
 * ============================================================
 */

import { Injectable, Logger } from '@nestjs/common';

import { Fingerprint } from '../interfaces/fingerprint.interface';
import { RequestContext } from '../interfaces/request-context.interface';
import { ThreatSeverity, ThreatType } from '../interfaces/threat.interface';

/**
 * ============================================================
 * Anomaly Service
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Behavioral deviation scoring
 * - Risk signal aggregation
 * - Baseline comparison heuristics
 * - Threat classification assistance
 * ============================================================
 */

@Injectable()
export class AnomalyService {
  /**
   * ============================================================
   * Logger
   * ============================================================
   */

  private readonly logger = new Logger(AnomalyService.name);

  /**
   * ============================================================
   * Baseline Heuristics (Simplified Model)
   * ============================================================
   *
   * NOTE:
   * In production this should be replaced by:
   * - rolling behavioral baselines (Redis / TSDB)
   * - ML anomaly detection (Isolation Forest, LSTM)
   * - per-user adaptive profiling
   * ============================================================
   */

  private readonly BASELINE_REQUEST_VELOCITY = 10; // req/min
  private readonly BASELINE_ENTROPY = 3.5;

  /**
   * ============================================================
   * Main Scoring Entry
   * ============================================================
   */

  analyze(context: RequestContext): {
    anomalyScore: number;
    threatType: ThreatType;
    severity: ThreatSeverity;
  } {
    const fingerprint = context.fingerprint;

    if (!fingerprint) {
      return {
        anomalyScore: 0.2,
        threatType: ThreatType.UNKNOWN,
        severity: ThreatSeverity.LOW,
      };
    }

    /**
     * ==========================================================
     * Feature Extraction
     * ==========================================================
     */

    const velocity = fingerprint.behavior?.requestVelocity || 0;
    const entropy = fingerprint.entropy?.compositeEntropy || 0;
    const botProb = fingerprint.botProbability || 0;
    const replayRisk = fingerprint.replayRisk || 0;

    /**
     * ==========================================================
     * Velocity Deviation Score
     * ==========================================================
     */

    const velocityScore = Math.min(
      1,
      velocity / this.BASELINE_REQUEST_VELOCITY,
    );

    /**
     * ==========================================================
     * Entropy Deviation Score
     * ==========================================================
     */

    const entropyScore =
      entropy < this.BASELINE_ENTROPY
        ? 0.7
        : Math.min(1, entropy / (this.BASELINE_ENTROPY * 2));

    /**
     * ==========================================================
     * Composite Anomaly Score
     * ==========================================================
     *
     * Weighted deterministic model
     * ==========================================================
     */

    const anomalyScore =
      velocityScore * 0.35 +
      entropyScore * 0.25 +
      botProb * 0.25 +
      replayRisk * 0.15;

    /**
     * ==========================================================
     * Threat Classification
     * ==========================================================
     */

    let threatType = ThreatType.UNKNOWN;
    let severity = ThreatSeverity.LOW;

    if (anomalyScore > 0.85) {
      threatType = ThreatType.DISTRIBUTED_FLOODING;
      severity = ThreatSeverity.CRITICAL;
    } else if (anomalyScore > 0.7) {
      threatType = ThreatType.BEHAVIORAL_DEVIATION;
      severity = ThreatSeverity.HIGH;
    } else if (anomalyScore > 0.5) {
      threatType = ThreatType.SESSION_ANOMALY;
      severity = ThreatSeverity.MEDIUM;
    }

    /**
     * ==========================================================
     * Telemetry Logging
     * ==========================================================
     */

    this.logger.log({
      event: 'ANOMALY_ANALYSIS_COMPLETE',
      anomalyScore,
      threatType,
      severity,
      timestamp: Date.now(),
    });

    return {
      anomalyScore,
      threatType,
      severity,
    };
  }
}

