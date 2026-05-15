/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Request Metrics & Telemetry Interceptor
 * File: metrics.interceptor.ts
 * ============================================================
 *
 * PURPOSE:
 * Captures structured runtime metrics and
 * request-path telemetry across ASF pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Monitor request latency
 * - Measure gateway performance
 * - Detect abnormal execution patterns
 * - Generate observability telemetry
 * - Support adaptive risk analytics
 * - Track infrastructure degradation
 *
 * DESIGN PRINCIPLES:
 * - Low-overhead instrumentation
 * - Non-blocking telemetry generation
 * - Deterministic timing collection
 * - Structured observability
 * - Minimal latency inflation
 *
 * IMPORTANT:
 * This interceptor operates directly
 * in the request execution path.
 *
 * Heavy telemetry aggregation MUST be:
 * - asynchronous
 * - buffered
 * - streamed externally
 *
 * NEVER:
 * - block request execution
 * - perform heavy analytics inline
 * - synchronously persist metrics
 * - expose internal telemetry publicly
 *
 * ============================================================
 */

import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';

import { Observable } from 'rxjs';

import { tap } from 'rxjs/operators';

import { Request, Response } from 'express';

import { performance } from 'perf_hooks';

/**
 * ============================================================
 * Request Metrics Interceptor
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Request latency measurement
 * - Response telemetry generation
 * - Performance observability
 * - Runtime diagnostics
 * ============================================================
 */

@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  /**
   * ============================================================
   * Structured Telemetry Logger
   * ============================================================
   */

  private readonly logger = new Logger(MetricsInterceptor.name);

  /**
   * ============================================================
   * Request Interception Entry Point
   * ============================================================
   */

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const httpContext = context.switchToHttp();

    const request = httpContext.getRequest<Request>();

    const response = httpContext.getResponse<Response>();

    /**
     * ==========================================================
     * High-Resolution Timing Start
     * ==========================================================
     */

    const startTime = performance.now();

    /**
     * ==========================================================
     * Request Metadata Extraction
     * ==========================================================
     */

    const method = request.method;

    const path = request.originalUrl;

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const userAgent = request.headers['user-agent'] || 'unknown';

    const requestId = (request.headers['x-request-id'] as string) || null;

    const correlationId =
      (request.headers['x-correlation-id'] as string) || null;

    /**
     * ==========================================================
     * Security Context Resolution
     * ==========================================================
     */

    const securityContext = (request as any).securityContext || null;

    /**
     * ==========================================================
     * Downstream Execution Monitoring
     * ==========================================================
     */

    return next.handle().pipe(
      tap({
        next: () => {
          /**
           * ====================================================
           * Request Completion Timing
           * ====================================================
           */

          const endTime = performance.now();

          const latency = Number((endTime - startTime).toFixed(2));

          /**
           * ====================================================
           * HTTP Response Metadata
           * ====================================================
           */

          const statusCode = response.statusCode;

          /**
           * ====================================================
           * Latency Classification
           * ====================================================
           */

          let latencyClassification = 'optimal';

          if (latency >= 50) {
            latencyClassification = 'elevated';
          }

          if (latency >= 150) {
            latencyClassification = 'degraded';
          }

          if (latency >= 500) {
            latencyClassification = 'critical';
          }

          /**
           * ====================================================
           * Structured Metrics Telemetry
           * ====================================================
           */

          const telemetry = {
            event: 'REQUEST_COMPLETED',

            timestamp: Date.now(),

            method,

            path,

            statusCode,

            latencyMs: latency,

            latencyClassification,

            ip,

            userAgent,

            requestId,

            correlationId,

            suspicious: securityContext?.suspicious || false,

            suspicionScore: securityContext?.suspicionScore || 0,
          };

          /**
           * ====================================================
           * Performance Threshold Monitoring
           * ====================================================
           */

          if (latency >= 200) {
            this.logger.warn({
              event: 'HIGH_LATENCY_REQUEST_DETECTED',

              telemetry,
            });
          } else {
            this.logger.log(telemetry);
          }

          /**
           * ====================================================
           * Future Extension Points
           * ====================================================
           *
           * RECOMMENDED:
           * - Prometheus metrics export
           * - OpenTelemetry integration
           * - Kafka telemetry streaming
           * - Redis metrics buffering
           * - Adaptive anomaly scoring
           * ====================================================
           */
        },

        error: (error) => {
          /**
           * ====================================================
           * Failed Request Telemetry
           * ====================================================
           */

          const endTime = performance.now();

          const latency = Number((endTime - startTime).toFixed(2));

          this.logger.error({
            event: 'REQUEST_FAILED',

            timestamp: Date.now(),

            method,

            path,

            latencyMs: latency,

            ip,

            requestId,

            correlationId,

            error: error instanceof Error ? error.message : 'Unknown error',
          });
        },
      }),
    );
  }
}
