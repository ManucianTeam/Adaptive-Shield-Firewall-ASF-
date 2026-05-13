// apps/auth-service/src/auth/guards/suspicious.guard.ts

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';

import { Request } from 'express';

import { RiskScoreService } from '../../ai-security/services/risk-score.service';

import { AnomalyAnalyzer } from '../../ai-security/analyzers/anomaly.analyzer';
import { BehaviorAnalyzer } from '../../ai-security/analyzers/behavior.analyzer';
import { GeoAnalyzer } from '../../ai-security/analyzers/geo.analyzer';
import { TimingAnalyzer } from '../../ai-security/analyzers/timing.analyzer';

/**
 * ============================================================================
 * ASF Suspicious Activity Guard
 * ============================================================================
 *
 * Adaptive AI-assisted security guard responsible for:
 *
 *  - hostile request detection
 *  - behavioral anomaly correlation
 *  - automation signature detection
 *  - suspicious geo-intelligence validation
 *  - timing attack identification
 *  - adaptive access mitigation
 *
 * Core Security Capabilities:
 *
 *  - distributed threat analysis
 *  - deterministic risk aggregation
 *  - impossible travel detection
 *  - request-frequency analysis
 *  - bot-behavior identification
 *  - adaptive trust scoring
 *
 * Enforcement Strategy:
 *
 *  - analyze incoming request telemetry
 *  - aggregate multi-analyzer risk signals
 *  - classify hostile behaviors
 *  - block high-risk authentication flows
 *  - allow low-risk trusted traffic
 *
 * Designed For:
 *
 *  - Zero Trust infrastructures
 *  - adaptive API gateways
 *  - distributed authentication systems
 *  - AI-assisted access-control pipelines
 *
 * ============================================================================
 */

@Injectable()
export class SuspiciousGuard
  implements CanActivate
{
  private readonly logger = new Logger(
    SuspiciousGuard.name,
  );

  constructor(
    private readonly anomalyAnalyzer: AnomalyAnalyzer,

    private readonly behaviorAnalyzer: BehaviorAnalyzer,

    private readonly geoAnalyzer: GeoAnalyzer,

    private readonly timingAnalyzer: TimingAnalyzer,

    private readonly riskScoreService: RiskScoreService,
  ) {}

  /**
   * --------------------------------------------------------------------------
   * Adaptive Threat Validation Pipeline
   * --------------------------------------------------------------------------
   */

  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    const request =
      context
        .switchToHttp()
        .getRequest<Request>();

    /**
     * ------------------------------------------------------------------------
     * Request Telemetry Extraction
     * ------------------------------------------------------------------------
     */

    const ip =
      this.extractIp(request);

    const userAgent =
      request.headers[
        'user-agent'
      ] || '';

    const fingerprint =
      String(
        request.headers[
          'x-device-fingerprint'
        ] || '',
      );

    /**
     * ------------------------------------------------------------------------
     * Security Analyzer Execution
     * ------------------------------------------------------------------------
     */

    const anomalyResult =
      this.anomalyAnalyzer.analyze({
        ip,
        userAgent,
        fingerprint,
      });

    const behaviorResult =
      this.behaviorAnalyzer.analyze({
        ip,
        userAgent,
        fingerprint,
      });

    const geoResult =
      this.geoAnalyzer.analyze({
        ip,
      });

    const timingResult =
      this.timingAnalyzer.analyze({
        timestamp: Date.now(),
        ip,
      });

    /**
     * ------------------------------------------------------------------------
     * Unified Threat Aggregation
     * ------------------------------------------------------------------------
     */

    const aggregated =
      this.riskScoreService.aggregate({
        anomaly: anomalyResult,
        behavior: behaviorResult,
        geo: geoResult,
        timing: timingResult,
      });

    /**
     * ------------------------------------------------------------------------
     * Security Telemetry
     * ------------------------------------------------------------------------
     */

    this.logger.warn({
      message:
        'Adaptive threat analysis executed',

      ip,

      score:
        aggregated.globalScore,

      severity:
        aggregated.severity,

      blocked:
        aggregated.blocked,
    });

    /**
     * ------------------------------------------------------------------------
     * Automated Mitigation
     * ------------------------------------------------------------------------
     */

    if (aggregated.blocked) {
      throw new ForbiddenException({
        success: false,

        message:
          'Request blocked by adaptive security policy',

        security: {
          severity:
            aggregated.severity,

          score:
            aggregated.globalScore,

          hostileSignals:
            aggregated
              .correlation
              .hostileSignals,
        },
      });
    }

    /**
     * ------------------------------------------------------------------------
     * Inject Security Context
     * ------------------------------------------------------------------------
     */

    request['security'] = {
      threat: aggregated,
    };

    return true;
  }

  /**
   * --------------------------------------------------------------------------
   * Client IP Extraction
   * --------------------------------------------------------------------------
   */

  private extractIp(
    request: Request,
  ): string {
    const forwarded =
      request.headers[
        'x-forwarded-for'
      ];

    if (
      typeof forwarded ===
      'string'
    ) {
      return forwarded
        .split(',')[0]
        .trim();
    }

    return (
      request.ip ||
      request.socket
        ?.remoteAddress ||
      '0.0.0.0'
    );
  }
}