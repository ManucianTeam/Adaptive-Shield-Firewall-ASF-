/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Structured Request Logging Middleware
 * File: logging.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides deterministic, structured request logging
 * across ASF gateway and microservice boundaries.
 *
 * SECURITY OBJECTIVES:
 * - Enable forensic traceability
 * - Support incident response workflows
 * - Provide behavioral telemetry signals
 * - Correlate distributed requests
 * - Monitor abnormal traffic patterns
 *
 * DESIGN PRINCIPLES:
 * - Minimal overhead logging
 * - Structured JSON telemetry
 * - Non-blocking execution
 * - Correlation-first observability
 * - Sensitive data avoidance by design
 *
 * IMPORTANT:
 * NEVER log:
 * - raw credentials or tokens
 * - full request bodies containing secrets
 * - sensitive headers (Authorization, Cookie)
 * - internal stack traces in normal flow
 *
 * Logs SHOULD be:
 * - structured
 * - minimal
 * - correlation-aware
 *
 * ============================================================
 */

import { Injectable, Logger, NestMiddleware } from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

/**
 * ============================================================
 * Logging Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Request lifecycle logging
 * - Correlation tracking
 * - Lightweight telemetry emission
 * - Security signal enrichment
 * ============================================================
 */

@Injectable()
export class LoggingMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Structured Logger Instance
   * ============================================================
   */

  private readonly logger = new Logger(LoggingMiddleware.name);

  /**
   * ============================================================
   * Middleware Entry Point
   * ============================================================
   */

  use(request: Request, response: Response, next: NextFunction): void {
    /**
     * ==========================================================
     * Request Metadata Extraction
     * ==========================================================
     */

    const startTime = Date.now();

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const method = request.method;

    const path = request.originalUrl;

    const userAgent = String(request.headers['user-agent'] || '');

    const requestId =
      (request.headers['x-request-id'] as string) || this.generateRequestId();

    const correlationId =
      (request.headers['x-correlation-id'] as string) || requestId;

    /**
     * ==========================================================
     * Inject Correlation Context
     * ==========================================================
     */

    (request as any).requestContext = {
      requestId,
      correlationId,
      receivedAt: startTime,
    };

    /**
     * ==========================================================
     * Response Completion Hook
     * ==========================================================
     */

    response.on('finish', () => {
      const latency = Date.now() - startTime;

      const statusCode = response.statusCode;

      /**
       * ======================================================
       * Log Level Classification
       * ======================================================
       */

      const level =
        statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warn' : 'log';

      /**
       * ======================================================
       * Structured Log Payload
       * ======================================================
       */

      const logPayload = {
        event: 'HTTP_REQUEST',

        method,

        path,

        statusCode,

        latencyMs: latency,

        ip,

        userAgent,

        requestId,

        correlationId,

        timestamp: Date.now(),
      };

      /**
       * ======================================================
       * Emit Log
       * ======================================================
       */

      if (level === 'error') {
        this.logger.error(logPayload);
      } else if (level === 'warn') {
        this.logger.warn(logPayload);
      } else {
        this.logger.log(logPayload);
      }
    });

    /**
     * ==========================================================
     * Continue Pipeline
     * ==========================================================
     */

    next();
  }

  /**
   * ============================================================
   * Request ID Generator
   * ============================================================
   *
   * PURPOSE:
   * Generates lightweight deterministic identifier
   * for request traceability when missing.
   * ============================================================
   */

  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
  }
}
