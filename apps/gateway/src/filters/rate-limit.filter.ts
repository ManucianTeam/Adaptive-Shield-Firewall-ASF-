/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Rate Limit Exception Security Filter
 * File: rate-limit.filter.ts
 * ============================================================
 *
 * PURPOSE:
 * Specialized exception filter responsible for
 * intercepting and normalizing request-throttling
 * and rate-limit enforcement events.
 *
 * SECURITY OBJECTIVES:
 * - Mitigate request flooding
 * - Normalize throttling responses
 * - Generate abuse telemetry
 * - Detect bot amplification patterns
 * - Support adaptive traffic intelligence
 *
 * DESIGN PRINCIPLES:
 * - Deterministic throttling responses
 * - Minimal policy disclosure
 * - Structured observability
 * - Low-overhead enforcement
 * - Security telemetry enrichment
 *
 * IMPORTANT:
 * NEVER expose:
 * - internal threshold values
 * - dynamic scoring weights
 * - mitigation heuristics
 * - rate-limiter topology
 * - Redis key structures
 *
 * ============================================================
 */

import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
  Logger,
} from '@nestjs/common';

import { Request, Response } from 'express';

import { ThrottlerException } from '@nestjs/throttler';

/**
 * ============================================================
 * Rate Limit Exception Filter
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Traffic abuse normalization
 * - Structured throttling responses
 * - Security telemetry generation
 * - Abuse pattern observability
 * ============================================================
 */

@Catch(ThrottlerException)
export class RateLimitFilter implements ExceptionFilter {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(RateLimitFilter.name);

  /**
   * ============================================================
   * Rate-Limit Interceptor
   * ============================================================
   */

  catch(exception: ThrottlerException, host: ArgumentsHost): void {
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
     * Abuse Telemetry Payload
     * ==========================================================
     */

    const telemetry = {
      event: 'RATE_LIMIT_TRIGGERED',

      timestamp: Date.now(),

      statusCode: HttpStatus.TOO_MANY_REQUESTS,

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
     * Repeated rate-limit violations may indicate:
     * - bot automation
     * - credential stuffing
     * - scraping activity
     * - API abuse
     * - distributed flooding
     * ==========================================================
     */

    this.logger.warn({
      message: 'Rate-limit enforcement triggered.',

      telemetry,
    });

    /**
     * ==========================================================
     * Sanitized Throttling Response
     * ==========================================================
     *
     * Prevents:
     * - mitigation strategy disclosure
     * - threshold fingerprinting
     * - adaptive policy enumeration
     * ==========================================================
     */

    response.status(HttpStatus.TOO_MANY_REQUESTS).json({
      success: false,

      statusCode: HttpStatus.TOO_MANY_REQUESTS,

      timestamp: new Date().toISOString(),

      path: request.originalUrl,

      requestId,

      correlationId,

      error: {
        code: 'RATE_LIMIT_EXCEEDED',

        message: 'Request rate exceeded. Please retry later.',
      },
    });
  }
}
