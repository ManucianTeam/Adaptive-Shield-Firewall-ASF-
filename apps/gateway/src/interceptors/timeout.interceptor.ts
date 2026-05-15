/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Request Timeout Enforcement Interceptor
 * File: timeout.interceptor.ts
 * ============================================================
 *
 * PURPOSE:
 * Enforces deterministic execution-time boundaries
 * across ASF request-processing pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Prevent resource exhaustion attacks
 * - Mitigate slow-request abuse
 * - Reduce thread/event-loop starvation
 * - Protect downstream service stability
 * - Enforce latency budget boundaries
 *
 * DESIGN PRINCIPLES:
 * - Low-overhead timeout enforcement
 * - Deterministic execution ceilings
 * - Structured timeout telemetry
 * - Minimal event-loop interference
 * - Predictable failure semantics
 *
 * IMPORTANT:
 * Timeouts are critical for:
 * - API gateways
 * - distributed systems
 * - behavioral-analysis engines
 * - anomaly pipelines
 * - external dependency isolation
 *
 * NEVER:
 * - allow unbounded request execution
 * - perform blocking operations inline
 * - expose infrastructure timeout topology
 * - rely only on upstream proxy timeouts
 *
 * ============================================================
 */

import {
  CallHandler,
  ExecutionContext,
  GatewayTimeoutException,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';

import { Observable, throwError } from 'rxjs';

import { catchError, timeout } from 'rxjs/operators';

import { Request } from 'express';

/**
 * ============================================================
 * Request Timeout Interceptor
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Request timeout enforcement
 * - Latency budget protection
 * - Execution observability
 * - Timeout telemetry generation
 * ============================================================
 */

@Injectable()
export class TimeoutInterceptor implements NestInterceptor {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(TimeoutInterceptor.name);

  /**
   * ============================================================
   * Default Execution Timeout
   * ============================================================
   *
   * NOTE:
   * Enterprise deployments should expose
   * adaptive timeout configuration via:
   * - environment configuration
   * - dynamic policy engine
   * - route-level policies
   * ============================================================
   */

  private readonly REQUEST_TIMEOUT_MS = 5000;

  /**
   * ============================================================
   * Interceptor Execution Entry Point
   * ============================================================
   */

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const httpContext = context.switchToHttp();

    const request = httpContext.getRequest<Request>();

    /**
     * ==========================================================
     * Request Metadata Extraction
     * ==========================================================
     */

    const method = request.method;

    const path = request.originalUrl;

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const requestId = (request.headers['x-request-id'] as string) || null;

    const correlationId =
      (request.headers['x-correlation-id'] as string) || null;

    /**
     * ==========================================================
     * Request Timeout Enforcement
     * ==========================================================
     */

    return next.handle().pipe(
      timeout(this.REQUEST_TIMEOUT_MS),

      /**
       * ========================================================
       * Timeout Exception Handling
       * ========================================================
       */

      catchError((error) => {
        /**
         * ======================================================
         * Timeout Detection
         * ======================================================
         */

        const isTimeout = error?.name === 'TimeoutError';

        if (isTimeout) {
          /**
           * ====================================================
           * Structured Timeout Telemetry
           * ====================================================
           */

          this.logger.warn({
            event: 'REQUEST_TIMEOUT_TRIGGERED',

            timeoutMs: this.REQUEST_TIMEOUT_MS,

            method,

            path,

            ip,

            requestId,

            correlationId,

            timestamp: Date.now(),
          });

          /**
           * ====================================================
           * Security Context Injection
           * ====================================================
           *
           * Slow requests may indicate:
           * - resource exhaustion attacks
           * - dependency degradation
           * - concurrency contention
           * - behavioral-analysis overload
           * ====================================================
           */

          (request as any).securityContext = {
            timeoutTriggered: true,

            latencyViolation: true,

            timeoutMs: this.REQUEST_TIMEOUT_MS,

            timestamp: Date.now(),
          };

          /**
           * ====================================================
           * Gateway Timeout Exception
           * ====================================================
           */

          return throwError(
            () =>
              new GatewayTimeoutException(
                'Request execution exceeded the permitted latency budget.',
              ),
          );
        }

        /**
         * ======================================================
         * Non-Timeout Error Propagation
         * ======================================================
         */

        return throwError(() => error);
      }),
    );
  }
}
