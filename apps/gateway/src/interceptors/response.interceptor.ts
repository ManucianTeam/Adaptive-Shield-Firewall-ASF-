/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Standardized Response Interceptor
 * File: response.interceptor.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides centralized outbound response
 * normalization and structured API response
 * formatting across ASF services.
 *
 * SECURITY OBJECTIVES:
 * - Enforce deterministic response contracts
 * - Prevent accidental metadata leakage
 * - Standardize response observability
 * - Support distributed request tracing
 * - Maintain gateway response integrity
 *
 * DESIGN PRINCIPLES:
 * - Minimal response overhead
 * - Deterministic output structure
 * - Consistent API semantics
 * - Lightweight execution path
 * - Structured telemetry compatibility
 *
 * IMPORTANT:
 * NEVER expose:
 * - internal stack traces
 * - ORM internals
 * - infrastructure topology
 * - Redis metadata
 * - hidden security fields
 * - private runtime state
 *
 * ============================================================
 */

import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';

import { Observable } from 'rxjs';

import { map } from 'rxjs/operators';

import { Request, Response } from 'express';

/**
 * ============================================================
 * Standardized Response Interceptor
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Response normalization
 * - Outbound metadata shaping
 * - Correlation propagation
 * - API consistency enforcement
 * ============================================================
 */

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  /**
   * ============================================================
   * Interceptor Execution Entry Point
   * ============================================================
   */

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const httpContext = context.switchToHttp();

    const request = httpContext.getRequest<Request>();

    const response = httpContext.getResponse<Response>();

    /**
     * ==========================================================
     * Correlation Metadata Extraction
     * ==========================================================
     */

    const requestId = (request.headers['x-request-id'] as string) || null;

    const correlationId =
      (request.headers['x-correlation-id'] as string) || null;

    /**
     * ==========================================================
     * Response Transformation Pipeline
     * ==========================================================
     */

    return next.handle().pipe(
      map((data: unknown) => {
        /**
         * ======================================================
         * HTTP Metadata
         * ======================================================
         */

        const statusCode = response.statusCode;

        /**
         * ======================================================
         * Response Envelope
         * ======================================================
         *
         * STANDARD CONTRACT:
         * {
         *   success,
         *   statusCode,
         *   timestamp,
         *   path,
         *   requestId,
         *   correlationId,
         *   data
         * }
         * ======================================================
         */

        return {
          success: true,

          statusCode,

          timestamp: new Date().toISOString(),

          path: request.originalUrl,

          requestId,

          correlationId,

          /**
           * ====================================================
           * Response Payload
           * ====================================================
           */

          data,

          /**
           * ====================================================
           * Lightweight Response Metadata
           * ====================================================
           */

          metadata: {
            method: request.method,

            processingNode: process.env.HOSTNAME || 'asf-node',

            version: process.env.APP_VERSION || '1.0.0',
          },
        };
      }),
    );
  }
}
