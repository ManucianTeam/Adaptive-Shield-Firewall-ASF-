/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Response Transformation Interceptor
 * File: transform.interceptor.ts
 * ============================================================
 *
 * PURPOSE:
 * Performs deterministic outbound response
 * transformation, normalization, and payload
 * shaping across ASF service boundaries.
 *
 * SECURITY OBJECTIVES:
 * - Prevent sensitive metadata leakage
 * - Enforce consistent response contracts
 * - Standardize distributed API semantics
 * - Support observability correlation
 * - Reduce serialization inconsistencies
 *
 * DESIGN PRINCIPLES:
 * - Lightweight response transformation
 * - Deterministic payload structure
 * - Minimal serialization overhead
 * - Zero-trust response normalization
 * - Structured observability compatibility
 *
 * IMPORTANT:
 * NEVER expose:
 * - internal ORM metadata
 * - stack traces
 * - hidden entity properties
 * - infrastructure topology
 * - internal security scores
 * - private runtime state
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

import { map } from 'rxjs/operators';

import { Request, Response } from 'express';

/**
 * ============================================================
 * Response Transformation Interceptor
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Response normalization
 * - Outbound payload transformation
 * - Metadata sanitization
 * - Correlation propagation
 * ============================================================
 */

@Injectable()
export class TransformInterceptor implements NestInterceptor {
  /**
   * ============================================================
   * Structured Telemetry Logger
   * ============================================================
   */

  private readonly logger = new Logger(TransformInterceptor.name);

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
     * Downstream Response Transformation
     * ==========================================================
     */

    return next.handle().pipe(
      map((payload: unknown) => {
        /**
         * ======================================================
         * Payload Sanitization
         * ======================================================
         */

        const sanitizedPayload = this.sanitizePayload(payload);

        /**
         * ======================================================
         * HTTP Metadata
         * ======================================================
         */

        const statusCode = response.statusCode;

        /**
         * ======================================================
         * Standardized Response Envelope
         * ======================================================
         */

        const transformedResponse = {
          success: true,

          statusCode,

          timestamp: new Date().toISOString(),

          path: request.originalUrl,

          requestId,

          correlationId,

          /**
           * ====================================================
           * Transformed Payload
           * ====================================================
           */

          data: sanitizedPayload,

          /**
           * ====================================================
           * Runtime Metadata
           * ====================================================
           */

          metadata: {
            method: request.method,

            processingNode: process.env.HOSTNAME || 'asf-node',

            service: process.env.SERVICE_NAME || 'adaptive-shield-firewall',

            version: process.env.APP_VERSION || '1.0.0',
          },
        };

        /**
         * ======================================================
         * Response Telemetry
         * ======================================================
         */

        this.logger.log({
          event: 'RESPONSE_TRANSFORMED',

          statusCode,

          path: request.originalUrl,

          requestId,

          correlationId,

          timestamp: Date.now(),
        });

        return transformedResponse;
      }),
    );
  }

  /**
   * ============================================================
   * Recursive Payload Sanitizer
   * ============================================================
   *
   * PURPOSE:
   * Removes internal/private properties from
   * outbound payload structures.
   *
   * TARGETS:
   * - password fields
   * - token metadata
   * - internal identifiers
   * - hidden ORM properties
   * - runtime internals
   * ============================================================
   */

  private sanitizePayload(payload: any): any {
    /**
     * ==========================================================
     * Array Traversal
     * ==========================================================
     */

    if (Array.isArray(payload)) {
      return payload.map((item) => this.sanitizePayload(item));
    }

    /**
     * ==========================================================
     * Object Traversal
     * ==========================================================
     */

    if (payload && typeof payload === 'object') {
      const sanitizedObject: Record<string, unknown> = {};

      const forbiddenFields = [
        'password',
        'passwordHash',
        'secret',
        'token',
        'refreshToken',
        'accessToken',
        'jwt',
        '__v',
        '_internal',
        '_private',
      ];

      for (const key of Object.keys(payload)) {
        /**
         * ======================================================
         * Forbidden Field Filtering
         * ======================================================
         */

        if (forbiddenFields.includes(key)) {
          continue;
        }

        sanitizedObject[key] = this.sanitizePayload(payload[key]);
      }

      return sanitizedObject;
    }

    /**
     * ==========================================================
     * Primitive Passthrough
     * ==========================================================
     */

    return payload;
  }
}
