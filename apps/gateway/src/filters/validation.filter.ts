/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Validation Exception Security Filter
 * File: validation.filter.ts
 * ============================================================
 *
 * PURPOSE:
 * Specialized exception filter responsible for
 * intercepting and normalizing validation-layer
 * exceptions across ASF request pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Prevent malformed payload execution
 * - Normalize validation responses
 * - Reduce injection attack surface
 * - Generate structured validation telemetry
 * - Support forensic request tracing
 *
 * DESIGN PRINCIPLES:
 * - Deterministic validation contracts
 * - Minimal information disclosure
 * - Structured observability
 * - Low-latency validation interception
 * - Zero-trust request processing
 *
 * IMPORTANT:
 * NEVER expose:
 * - DTO internals
 * - validation schemas
 * - parser internals
 * - stack traces
 * - internal decorators
 * - infrastructure metadata
 *
 * ============================================================
 */

import {
  ArgumentsHost,
  BadRequestException,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
} from '@nestjs/common';

import { Request, Response } from 'express';

/**
 * ============================================================
 * Validation Exception Filter
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Validation error normalization
 * - Structured request rejection
 * - Security telemetry generation
 * - Malformed payload observability
 * ============================================================
 */

@Catch(BadRequestException)
export class ValidationFilter implements ExceptionFilter {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(ValidationFilter.name);

  /**
   * ============================================================
   * Validation Exception Interceptor
   * ============================================================
   */

  catch(exception: BadRequestException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();

    const request = ctx.getRequest<Request>();

    const response = ctx.getResponse<Response>();

    /**
     * ==========================================================
     * Exception Payload Extraction
     * ==========================================================
     */

    const exceptionResponse = exception.getResponse();

    /**
     * ==========================================================
     * Request Correlation Metadata
     * ==========================================================
     */

    const requestId = (request.headers['x-request-id'] as string) || null;

    const correlationId =
      (request.headers['x-correlation-id'] as string) || null;

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const userAgent = request.headers['user-agent'] || 'unknown';

    /**
     * ==========================================================
     * Validation Message Resolution
     * ==========================================================
     */

    let validationErrors: string[] = ['Invalid request payload.'];

    if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
      const responseObject = exceptionResponse as Record<string, unknown>;

      if (Array.isArray(responseObject.message)) {
        validationErrors = responseObject.message.map((msg) => String(msg));
      }
    }

    /**
     * ==========================================================
     * Validation Telemetry Object
     * ==========================================================
     */

    const telemetry = {
      event: 'VALIDATION_FAILURE',

      timestamp: Date.now(),

      statusCode: HttpStatus.BAD_REQUEST,

      method: request.method,

      path: request.originalUrl,

      ip,

      userAgent,

      requestId,

      correlationId,

      validationErrorCount: validationErrors.length,
    };

    /**
     * ==========================================================
     * Structured Security Logging
     * ==========================================================
     *
     * IMPORTANT:
     * Validation anomalies may indicate:
     * - injection probing
     * - malformed automation traffic
     * - schema fuzzing
     * - endpoint reconnaissance
     * ==========================================================
     */

    this.logger.warn({
      message: 'Validation-layer rejection intercepted.',

      telemetry,

      validationErrors,
    });

    /**
     * ==========================================================
     * Sanitized Validation Response
     * ==========================================================
     *
     * Prevents:
     * - schema enumeration
     * - parser disclosure
     * - validation topology leakage
     * ==========================================================
     */

    response.status(HttpStatus.BAD_REQUEST).json({
      success: false,

      statusCode: HttpStatus.BAD_REQUEST,

      timestamp: new Date().toISOString(),

      path: request.originalUrl,

      requestId,

      correlationId,

      error: {
        code: 'VALIDATION_FAILURE',

        message: 'The request payload failed validation.',

        details: validationErrors,
      },
    });
  }
}
