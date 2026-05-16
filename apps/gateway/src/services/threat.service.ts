/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Adaptive Threat Intelligence Service
 * File: threat.service.ts
 * ============================================================
 *
 * PURPOSE:
 * Centralized threat evaluation and adaptive risk
 * orchestration engine for distributed applications.
 *
 * This service aggregates:
 * - anomaly analysis
 * - reputation intelligence
 * - behavioral deviation scoring
 * - distributed attack heuristics
 * - session trust analysis
 * - fingerprint telemetry
 * - mitigation recommendations
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Detect malicious behavior patterns
 * - Provide adaptive threat scoring
 * - Support zero-trust architectures
 * - Coordinate mitigation systems
 * - Reduce false positives
 * - Enable real-time enforcement
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Deterministic evaluation
 * - Stateless orchestration
 * - Modular signal aggregation
 * - Low-latency execution
 * - Future AI extensibility
 *
 * ============================================================
 *
 * IMPORTANT:
 * Threat intelligence is probabilistic.
 *
 * NEVER:
 * - trust single-signal detection
 * - expose internal scoring models
 * - hard-block solely from one heuristic
 * - assume benign infrastructure is safe
 *
 * ============================================================
 */

import { Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'crypto';

import { Request } from 'express';

import { RequestContext } from '../interfaces/request-context.interface';

import { ThreatSeverity, ThreatType } from '../interfaces/threat.interface';

import { AnomalyService } from './anomaly.service';
import { ReputationService } from './reputation.service';
import { SessionService } from './session.service';
import { ThreatCorrelationService } from './threat-correlation.service';

/**
 * ============================================================
 * Threat Evaluation Result
 * ============================================================
 */

export interface ThreatEvaluationResult {
  requestId: string;

  threatScore: number;

  threatType: ThreatType;

  severity: ThreatSeverity;

  trusted: boolean;

  blocked: boolean;

  indicators: string[];

  telemetry: Record<string, unknown>;
}

/**
 * ============================================================
 * Threat Service
 * ============================================================
 */

@Injectable()
export class ThreatService {
  /**
   * ==========================================================
   * Logger
   * ==========================================================
   */

  private readonly logger = new Logger(ThreatService.name);

  /**
   * ==========================================================
   * Constructor
   * ==========================================================
   */

  constructor(
    private readonly anomalyService: AnomalyService,

    private readonly reputationService: ReputationService,

    private readonly sessionService: SessionService,

    private readonly correlationService: ThreatCorrelationService,
  ) {}

  /**
   * ==========================================================
   * Main Threat Evaluation Pipeline
   * ==========================================================
   */

  async evaluate(
    context: RequestContext,

    request: Request,
  ): Promise<ThreatEvaluationResult> {
    /**
     * ========================================================
     * Request Identity
     * ========================================================
     */
    context.requestId = context.requestId || randomUUID();
    const requestId = context.requestId;

    const indicators: string[] = [];

    /**
     * ========================================================
     * Session Intelligence
     * ========================================================
     */

    let sessionRisk = 0;

    const sessionId = request.headers['x-session-id'] as string;

    if (sessionId) {
      const sessionValidation = await this.sessionService.validateSession(
        sessionId,
        request,
      );

      indicators.push(...sessionValidation.indicators);

      if (sessionValidation.riskDetected) {
        sessionRisk += 0.25;
      }
    } else {
      indicators.push('SESSION_NOT_PRESENT');

      sessionRisk += 0.1;
    }

    /**
     * ========================================================
     * Anomaly Intelligence
     * ========================================================
     */

    const anomalyResult = this.anomalyService.analyze(context);

    indicators.push(
      `ANOMALY_SCORE_${Math.round(anomalyResult.anomalyScore * 100)}`,
    );

    /**
     * ========================================================
     * Reputation Intelligence
     * ========================================================
     */

    const reputationResult = await this.reputationService.evaluate(context);

    indicators.push(...reputationResult.indicators);

    /**
     * ========================================================
     * Correlation Intelligence
     * ========================================================
     */

    const correlationResult = this.correlationService.correlate(context);

    indicators.push(...correlationResult.indicators);

    /**
     * ========================================================
     * Composite Threat Score
     * ========================================================
     *
     * Weighted deterministic model
     * ========================================================
     */

    const threatScore =
      anomalyResult.anomalyScore * 0.35 +
      (1 - reputationResult.trustScore) * 0.3 +
      correlationResult.confidence * 0.25 +
      sessionRisk * 0.1;

    /**
     * ========================================================
     * Normalize Threat Score
     * ========================================================
     */

    const normalizedThreatScore = Math.max(0, Math.min(1, threatScore));

    /**
     * ========================================================
     * Threat Classification
     * ========================================================
     */

    let threatType = ThreatType.UNKNOWN;

    let severity = ThreatSeverity.LOW;

    if (normalizedThreatScore >= 0.9) {
      threatType = ThreatType.DISTRIBUTED_FLOODING;

      severity = ThreatSeverity.CRITICAL;
    } else if (normalizedThreatScore >= 0.75) {
      threatType = ThreatType.AUTOMATED_ABUSE;

      severity = ThreatSeverity.HIGH;
    } else if (normalizedThreatScore >= 0.5) {
      threatType = ThreatType.BEHAVIORAL_DEVIATION;

      severity = ThreatSeverity.MEDIUM;
    }

    /**
     * ========================================================
     * Trust Evaluation
     * ========================================================
     */

    const trusted = normalizedThreatScore < 0.4;

    /**
     * ========================================================
     * Adaptive Blocking Logic
     * ========================================================
     */

    const blocked = normalizedThreatScore >= 0.92;

    if (blocked) {
      indicators.push('ADAPTIVE_BLOCK_TRIGGERED');
    }

    /**
     * ========================================================
     * Telemetry Object
     * ========================================================
     */

    const telemetry = {
      anomalyScore: anomalyResult.anomalyScore,

      trustScore: reputationResult.trustScore,

      correlationConfidence: correlationResult.confidence,

      sessionRisk,

      reputationLevel: reputationResult.reputationLevel,

      mitigationRecommended: correlationResult.mitigationRecommended,
    };

    /**
     * ========================================================
     * Threat Telemetry Logging
     * ========================================================
     */

    this.logger.warn({
      event: 'THREAT_EVALUATION_COMPLETE',

      requestId,

      threatScore: normalizedThreatScore,

      threatType,

      severity,

      trusted,

      blocked,

      indicators,

      telemetry,

      timestamp: Date.now(),
    });

    /**
     * ========================================================
     * Final Result
     * ========================================================
     */

    return {
      requestId,

      threatScore: normalizedThreatScore,

      threatType,

      severity,

      trusted,

      blocked,

      indicators,

      telemetry,
    };
  }
}
