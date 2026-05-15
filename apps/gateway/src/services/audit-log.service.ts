/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Distributed Threat Correlation Engine
 * File: threat-correlation.service.ts
 * ============================================================
 *
 * PURPOSE:
 * Correlates distributed behavioral signals and security
 * telemetry into unified threat intelligence decisions.
 *
 * This engine aggregates:
 * - fingerprint anomalies
 * - session reputation
 * - geo deviations
 * - rate anomalies
 * - bot indicators
 * - replay attempts
 * - ASN intelligence
 * - distributed attack heuristics
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Detect coordinated attacks
 * - Build adaptive threat confidence
 * - Reduce false positives
 * - Support zero-trust enforcement
 * - Enable real-time mitigation
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Stateless deterministic evaluation
 * - Signal composability
 * - Lightweight execution path
 * - Future ML extensibility
 * - Event-driven architecture compatibility
 *
 * ============================================================
 *
 * IMPORTANT:
 * This service provides probabilistic risk intelligence.
 *
 * NEVER:
 * - rely on a single signal
 * - hard block solely on correlation score
 * - expose internal scoring weights
 * - assume trusted infrastructure is safe
 *
 * ============================================================
 */

import { Injectable, Logger } from '@nestjs/common';

import { randomUUID } from 'crypto';

import { RequestContext } from '../interfaces/request-context.interface';
import { ThreatSeverity, ThreatType } from '../interfaces/threat.interface';

/**
 * ============================================================
 * Correlation Result
 * ============================================================
 */

export interface ThreatCorrelationResult {
  correlationId: string;

  confidence: number;

  threatType: ThreatType;

  severity: ThreatSeverity;

  indicators: string[];

  mitigationRecommended: boolean;
}

/**
 * ============================================================
 * Threat Correlation Service
 * ============================================================
 */

@Injectable()
export class ThreatCorrelationService {
  /**
   * ==========================================================
   * Logger
   * ==========================================================
   */

  private readonly logger = new Logger(ThreatCorrelationService.name);

  /**
   * ==========================================================
   * Threshold Configuration
   * ==========================================================
   */

  private readonly HIGH_BOT_THRESHOLD = 0.8;
  private readonly HIGH_REPLAY_THRESHOLD = 0.7;
  private readonly HIGH_RATE_THRESHOLD = 25;

  /**
   * ==========================================================
   * Main Correlation Engine
   * ==========================================================
   */

  correlate(context: RequestContext): ThreatCorrelationResult {
    const correlationId = randomUUID();

    const indicators: string[] = [];

    let confidence = 0;

    /**
     * ========================================================
     * Fingerprint Signals
     * ========================================================
     */

    const fp = context.fingerprint;

    if (!fp) {
      return {
        correlationId,
        confidence: 0.15,
        threatType: ThreatType.UNKNOWN,
        severity: ThreatSeverity.LOW,
        indicators: ['FINGERPRINT_MISSING'],
        mitigationRecommended: false,
      };
    }

    /**
     * ========================================================
     * Bot Probability Analysis
     * ========================================================
     */

    if (fp.botProbability > this.HIGH_BOT_THRESHOLD) {
      confidence += 0.3;

      indicators.push('HIGH_BOT_PROBABILITY');
    }

    /**
     * ========================================================
     * Replay Attack Analysis
     * ========================================================
     */

    if (fp.replayRisk > this.HIGH_REPLAY_THRESHOLD) {
      confidence += 0.25;

      indicators.push('REPLAY_RISK_DETECTED');
    }

    /**
     * ========================================================
     * Velocity / Flood Analysis
     * ========================================================
     */

    const velocity = fp.behavior?.requestVelocity || 0;

    if (velocity > this.HIGH_RATE_THRESHOLD) {
      confidence += 0.25;

      indicators.push('ABNORMAL_REQUEST_VELOCITY');
    }

    /**
     * ========================================================
     * Geo Deviation Analysis
     * ========================================================
     */

    if (fp.geo?.impossibleTravelDetected) {
      confidence += 0.1;

      indicators.push('IMPOSSIBLE_TRAVEL_EVENT');
    }

    /**
     * ========================================================
     * ASN Reputation
     * ========================================================
     */

    if (fp.network?.isDatacenter) {
      confidence += 0.15;

      indicators.push('DATACENTER_ASN_TRAFFIC');
    }

    /**
     * ========================================================
     * Normalize Confidence
     * ========================================================
     */

    confidence = Math.min(1, confidence);

    /**
     * ========================================================
     * Threat Classification
     * ========================================================
     */

    let threatType = ThreatType.UNKNOWN;

    let severity = ThreatSeverity.LOW;

    if (confidence >= 0.85) {
      threatType = ThreatType.DISTRIBUTED_FLOODING;

      severity = ThreatSeverity.CRITICAL;
    } else if (confidence >= 0.7) {
      threatType = ThreatType.AUTOMATED_ABUSE;

      severity = ThreatSeverity.HIGH;
    } else if (confidence >= 0.45) {
      threatType = ThreatType.BEHAVIORAL_DEVIATION;

      severity = ThreatSeverity.MEDIUM;
    }

    /**
     * ========================================================
     * Mitigation Decision
     * ========================================================
     */

    const mitigationRecommended = confidence >= 0.7;

    /**
     * ========================================================
     * Telemetry Logging
     * ========================================================
     */

    this.logger.warn({
      event: 'THREAT_CORRELATION_COMPLETE',

      correlationId,

      confidence,

      threatType,

      severity,

      indicators,

      mitigationRecommended,

      timestamp: Date.now(),
    });

    /**
     * ========================================================
     * Return Result
     * ========================================================
     */

    return {
      correlationId,

      confidence,

      threatType,

      severity,

      indicators,

      mitigationRecommended,
    };
  }
}
