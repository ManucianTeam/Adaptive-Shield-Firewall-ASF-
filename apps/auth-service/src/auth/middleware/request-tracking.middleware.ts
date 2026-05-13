// apps/auth-service/src/auth/middleware/request-tracking.middleware.ts

import {
  Injectable,
  Logger,
  NestMiddleware,
} from '@nestjs/common';

import {
  NextFunction,
  Request,
  Response,
} from 'express';

import {
  randomUUID,
  createHash,
} from 'crypto';

/**
 * ============================================================================
 * ASF Distributed Request Tracking Middleware
 * ============================================================================
 *
 * Enterprise-grade request observability and forensic telemetry middleware
 * engineered for distributed Zero Trust authentication infrastructures.
 *
 * Core Responsibilities:
 *
 *  - distributed request tracing
 *  - security telemetry propagation
 *  - correlation ID orchestration
 *  - latency instrumentation
 *  - forensic-grade audit enrichment
 *  - adaptive security context propagation
 *  - AI-assisted behavioral telemetry collection
 *
 * Security Architecture:
 *
 *  - deterministic correlation pipelines
 *  - distributed trace compatibility
 *  - immutable request lineage tracking
 *  - gateway-level telemetry enrichment
 *  - horizontally scalable observability
 *
 * Integrated Ecosystem:
 *
 *  - OpenTelemetry
 *  - SIEM pipelines
 *  - Grafana / Loki
 *  - Elastic Stack
 *  - adaptive anomaly engines
 *  - distributed API gateways
 *
 * ============================================================================
 */

@Injectable()
export class RequestTrackingMiddleware
  implements NestMiddleware
{
  private readonly logger = new Logger(
    RequestTrackingMiddleware.name,
  );

  /**
   * --------------------------------------------------------------------------
   * Middleware Execution Pipeline
   * --------------------------------------------------------------------------
   */

  use(
    request: Request,
    response: Response,
    next: NextFunction,
  ): void {
    /**
     * ------------------------------------------------------------------------
     * Correlation Identifier Resolution
     * ------------------------------------------------------------------------
     */

    const correlationId =
      this.resolveCorrelationId(
        request,
      );

    /**
     * ------------------------------------------------------------------------
     * High-Resolution Request Timestamp
     * ------------------------------------------------------------------------
     */

    const startedAt =
      performance.now();

    const startedAtIso =
      new Date().toISOString();

    /**
     * ------------------------------------------------------------------------
     * Client Telemetry Extraction
     * ------------------------------------------------------------------------
     */

    const ip =
      this.extractIp(request);

    const method =
      request.method;

    const path =
      request.originalUrl;

    const userAgent =
      String(
        request.headers[
          'user-agent'
        ] || '',
      );

    const fingerprint =
      String(
        request.headers[
          'x-device-fingerprint'
        ] || '',
      );

    /**
     * ------------------------------------------------------------------------
     * Deterministic Trace Fingerprint
     * ------------------------------------------------------------------------
     */

    const traceSignature =
      createHash('sha256')
        .update(
          `${correlationId}:${ip}:${method}:${path}`,
        )
        .digest('hex');

    /**
     * ------------------------------------------------------------------------
     * Distributed Request Context Injection
     * ------------------------------------------------------------------------
     */

    request['tracking'] = {
      correlationId,
      traceSignature,
      startedAt,
      startedAtIso,
    };

    request['correlationId'] =
      correlationId;

    request['traceSignature'] =
      traceSignature;

    /**
     * ------------------------------------------------------------------------
     * Propagate Correlation Headers
     * ------------------------------------------------------------------------
     */

    response.setHeader(
      'x-correlation-id',
      correlationId,
    );

    response.setHeader(
      'x-trace-signature',
      traceSignature,
    );

    /**
     * ------------------------------------------------------------------------
     * Entry Security Telemetry
     * ------------------------------------------------------------------------
     */

    this.logger.log({
      event:
        'request_initialized',

      correlationId,

      traceSignature,

      method,

      path,

      ip,

      fingerprint,

      startedAt:
        startedAtIso,
    });

    /**
     * ------------------------------------------------------------------------
     * Completion Hook
     * ------------------------------------------------------------------------
     */

    response.on(
      'finish',
      () => {
        const completedAt =
          new Date().toISOString();

        const durationMs =
          Number(
            (
              performance.now() -
              startedAt
            ).toFixed(3),
          );

        /**
         * --------------------------------------------------------------------
         * Response Telemetry
         * --------------------------------------------------------------------
         */

        this.logger.log({
          event:
            'request_completed',

          correlationId,

          traceSignature,

          method,

          path,

          statusCode:
            response.statusCode,

          durationMs,

          completedAt,

          ip,
        });

        /**
         * --------------------------------------------------------------------
         * Suspicious Latency Heuristic
         * --------------------------------------------------------------------
         */

        if (
          durationMs < 5
        ) {
          this.logger.warn({
            event:
              'abnormal_request_latency_detected',

            correlationId,

            durationMs,

            ip,
          });
        }
      },
    );

    next();
  }

  /**
   * --------------------------------------------------------------------------
   * Correlation Identifier Resolver
   * --------------------------------------------------------------------------
   */

  private resolveCorrelationId(
    request: Request,
  ): string {
    const existing =
      request.headers[
        'x-correlation-id'
      ];

    if (
      typeof existing ===
      'string' &&
      existing.length > 0
    ) {
      return existing;
    }

    return randomUUID();
  }

  /**
   * --------------------------------------------------------------------------
   * Source IP Extraction
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