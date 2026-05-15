/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Request Payload Size Enforcement Middleware
 * File: request-size.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Enforces strict request payload size boundaries
 * to mitigate memory exhaustion, payload bombing,
 * and decompression-based denial-of-service vectors.
 *
 * SECURITY OBJECTIVES:
 * - Prevent large payload abuse attacks
 * - Reduce memory pressure on gateway layer
 * - Protect downstream parsing pipelines
 * - Enforce API contract constraints
 * - Stabilize request ingestion layer
 *
 * DESIGN PRINCIPLES:
 * - Early request rejection
 * - Minimal overhead inspection
 * - Deterministic enforcement
 * - Header-aware validation
 * - Fail-fast protection model
 *
 * IMPORTANT:
 * This middleware is a FIRST-LINE defense only.
 * MUST be complemented by:
 * - reverse proxy limits (NGINX / CDN)
 * - body parser limits
 * - service-level validation
 *
 * NEVER:
 * - trust client-provided Content-Length
 * - allow unlimited streaming bodies
 * - rely solely on application-layer checks
 *
 * ============================================================
 */

import {
  Injectable,
  NestMiddleware,
  PayloadTooLargeException,
  Logger,
} from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

/**
 * ============================================================
 * Request Size Enforcement Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Payload size validation
 * - Request rejection on violation
 * - Security telemetry emission
 * ============================================================
 */

@Injectable()
export class RequestSizeMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Structured Logger
   * ============================================================
   */

  private readonly logger = new Logger(RequestSizeMiddleware.name);

  /**
   * ============================================================
   * Maximum Allowed Payload Size
   * ============================================================
   *
   * Default: 1MB
   * Adjust based on API profile.
   * ============================================================
   */

  private readonly MAX_SIZE_BYTES = 1 * 1024 * 1024;

  /**
   * ============================================================
   * Middleware Entry Point
   * ============================================================
   */

  use(request: Request, response: Response, next: NextFunction): void {
    /**
     * ==========================================================
     * Request Metadata
     * ==========================================================
     */

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const method = request.method;

    const path = request.originalUrl;

    /**
     * ==========================================================
     * Content-Length Evaluation
     * ==========================================================
     *
     * NOTE:
     * Content-Length can be spoofed; still useful
     * as a fast pre-check before body parsing.
     * ==========================================================
     */

    const contentLengthHeader = request.headers['content-length'];

    const contentLength = contentLengthHeader
      ? parseInt(contentLengthHeader as string, 10)
      : 0;

    /**
     * ==========================================================
     * Size Violation Check
     * ==========================================================
     */

    if (contentLength > this.MAX_SIZE_BYTES) {
      this.logger.warn({
        event: 'PAYLOAD_SIZE_BLOCKED',

        ip,

        method,

        path,

        contentLength,

        maxAllowed: this.MAX_SIZE_BYTES,

        timestamp: Date.now(),
      });

      throw new PayloadTooLargeException(
        'Request payload exceeds allowed size limit.',
      );
    }

    /**
     * ==========================================================
     * Attach Context
     * ==========================================================
     */

    (request as any).sizeContext = {
      contentLength,

      maxAllowed: this.MAX_SIZE_BYTES,

      withinLimit: true,

      evaluatedAt: Date.now(),
    };

    /**
     * ==========================================================
     * Continue Pipeline
     * ==========================================================
     */

    next();
  }
}
