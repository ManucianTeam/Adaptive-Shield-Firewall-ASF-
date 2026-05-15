/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Global Exception Handling Layer
 * File: all-exception.filter.ts
 * ============================================================
 *
 * PURPOSE:
 * Centralized exception interception and secure
 * error normalization layer for ASF.
 *
 * SECURITY OBJECTIVES:
 * - Prevent internal information leakage
 * - Normalize outbound error responses
 * - Generate structured security telemetry
 * - Correlate exceptions with request context
 * - Support forensic observability pipelines
 * - Reduce attack surface disclosure
 *
 * DESIGN PRINCIPLES:
 * - Zero-trust error handling
 * - Deterministic response contracts
 * - Minimal exposure of internal state
 * - Structured security logging
 * - Low-overhead execution path
 *
 * IMPORTANT:
 * NEVER expose:
 * - stack traces
 * - database internals
 * - infrastructure topology
 * - Redis keys
 * - JWT secrets
 * - internal service metadata
 *
 * ============================================================
 */

import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';

import { Request, Response } from 'express';

/**
 * ============================================================
 * ASF Global Exception Filter
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Global exception interception
 * - Security-safe response formatting
 * - Structured audit logging
 * - Telemetry enrichment
 * - Threat observability integration
 * ============================================================
 */

@Catch()
export class AllExceptionFilter implements ExceptionFilter {
  /**
   * ============================================================
   * Internal Structured Logger
   * ============================================================
   */

  private readonly logger = new Logger(AllExceptionFilter.name);

  /**
   * ============================================================
   * Exception Interception Handler
   * ============================================================
   *
   * FLOW:
   * 1. Extract request context
   * 2. Normalize exception
   * 3. Generate correlation metadata
   * 4. Emit structured security log
   * 5. Return sanitized response
   * ============================================================
   */

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();

    const request = ctx.getRequest<Request>();

    const response = ctx.getResponse<Response>();

    /**
     * ==========================================================
     * Resolve HTTP Status
     * ==========================================================
     */

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    /**
     * ==========================================================
     * Resolve Exception Message
     * ==========================================================
     */

    const exceptionResponse =
      exception instanceof HttpException ? exception.getResponse() : null;

    const message =
      typeof exceptionResponse === 'object' && exceptionResponse !== null
        ? (exceptionResponse as any).message
        : 'Internal server error';

    /**
     * ==========================================================
     * Correlation & Telemetry Metadata
     * ==========================================================
     */

    const requestId = (request.headers['x-request-id'] as string) || null;

    const correlationId =
      (request.headers['x-correlation-id'] as string) || null;

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const userAgent = request.headers['user-agent'] || 'unknown';

    /**
     * ==========================================================
     * Security Telemetry Payload
     * ==========================================================
     */

    const telemetry = {
      timestamp: Date.now(),

      statusCode: status,

      method: request.method,

      path: request.originalUrl,

      ip,

      userAgent,

      requestId,

      correlationId,

      message,

      exceptionType:
        exception instanceof Error ? exception.name : 'UnknownException',
    };

    /**
     * ==========================================================
     * Structured Security Logging
     * ==========================================================
     *
     * IMPORTANT:
     * Stack traces should only be logged internally.
     * Never expose them to clients.
     * ==========================================================
     */

    this.logger.error({
      event: 'GLOBAL_EXCEPTION_CAUGHT',
      telemetry,

      stack: exception instanceof Error ? exception.stack : undefined,
    });

    /**
     * ==========================================================
     * Sanitized Response Contract
     * ==========================================================
     *
     * Prevents:
     * - Internal leakage
     * - Stack disclosure
     * - Service enumeration
     * - Infrastructure fingerprinting
     * ==========================================================
     */

    response.status(status).json({
      success: false,

      statusCode: status,

      timestamp: new Date().toISOString(),

      path: request.originalUrl,

      requestId,

      correlationId,

      error: {
        code: this.resolveErrorCode(status),

        message:
          status === HttpStatus.INTERNAL_SERVER_ERROR
            ? 'An unexpected internal error occurred.'
            : message,
      },
    });
  }

  /**
   * ============================================================
   * Internal Error Code Resolver
   * ============================================================
   *
   * PURPOSE:
   * Maps HTTP status codes to
   * stable security-oriented error identifiers.
   * ============================================================
   */

  private resolveErrorCode(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'INVALID_REQUEST';

      case HttpStatus.UNAUTHORIZED:
        return 'AUTHENTICATION_FAILED';

      case HttpStatus.FORBIDDEN:
        return 'ACCESS_DENIED';

      case HttpStatus.NOT_FOUND:
        return 'RESOURCE_NOT_FOUND';

      case HttpStatus.CONFLICT:
        return 'RESOURCE_CONFLICT';

      case HttpStatus.TOO_MANY_REQUESTS:
        return 'RATE_LIMIT_EXCEEDED';

      case HttpStatus.INTERNAL_SERVER_ERROR:
      default:
        return 'INTERNAL_SECURITY_EXCEPTION';
    }
  }
}
