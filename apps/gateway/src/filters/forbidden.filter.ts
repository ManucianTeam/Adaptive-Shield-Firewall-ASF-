/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Forbidden Exception Security Filter
 * File: forbidden.filter.ts
 * ============================================================
 *
 * PURPOSE:
 * Specialized exception filter responsible for
 * intercepting and normalizing authorization
 * denial events across ASF security layers.
 *
 * SECURITY OBJECTIVES:
 * - Prevent authorization-state leakage
 * - Normalize access denial responses
 * - Generate structured security telemetry
 * - Detect suspicious privilege escalation attempts
 * - Support incident investigation pipelines
 *
 * DESIGN PRINCIPLES:
 * - Zero-trust authorization handling
 * - Deterministic denial responses
 * - Minimal exposure of internal policies
 * - Structured forensic logging
 * - Low-overhead interception path
 *
 * IMPORTANT:
 * NEVER expose:
 * - RBAC internals
 * - policy engine logic
 * - permission structures
 * - role hierarchy
 * - infrastructure metadata
 * - security scoring internals
 *
 * ============================================================
 */

import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  ForbiddenException,
  HttpStatus,
  Logger,
} from '@nestjs/common';

import { Request, Response } from 'express';

/**
 * ============================================================
 * Forbidden Exception Filter
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Access denial normalization
 * - Security telemetry generation
 * - Authorization event logging
 * - Suspicious activity observability
 * ============================================================
 */

@Catch(ForbiddenException)
export class ForbiddenFilter implements ExceptionFilter {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(ForbiddenFilter.name);

  /**
   * ============================================================
   * Forbidden Exception Interceptor
   * ============================================================
   */

  catch(exception: ForbiddenException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();

    const request = ctx.getRequest<Request>();

    const response = ctx.getResponse<Response>();

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
     * Security Telemetry Object
     * ==========================================================
     */

    const telemetry = {
      event: 'ACCESS_DENIED',

      timestamp: Date.now(),

      statusCode: HttpStatus.FORBIDDEN,

      method: request.method,

      path: request.originalUrl,

      ip,

      userAgent,

      requestId,

      correlationId,
    };

    /**
     * ==========================================================
     * Structured Security Logging
     * ==========================================================
     *
     * IMPORTANT:
     * Access denial patterns may indicate:
     * - privilege escalation attempts
     * - token abuse
     * - lateral movement
     * - policy probing
     * ==========================================================
     */

    this.logger.warn({
      message: 'Forbidden access attempt intercepted.',

      telemetry,
    });

    /**
     * ==========================================================
     * Sanitized Forbidden Response
     * ==========================================================
     *
     * Prevents:
     * - RBAC enumeration
     * - policy fingerprinting
     * - authorization topology leakage
     * ==========================================================
     */

    response.status(HttpStatus.FORBIDDEN).json({
      success: false,

      statusCode: HttpStatus.FORBIDDEN,

      timestamp: new Date().toISOString(),

      path: request.originalUrl,

      requestId,

      correlationId,

      error: {
        code: 'ACCESS_DENIED',

        message: 'You do not have permission to access this resource.',
      },
    });
  }
}
