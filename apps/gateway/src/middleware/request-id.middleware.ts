/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Request Identity Propagation Middleware
 * File: request-id.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Ensures every request carries a deterministic
 * unique identifier for traceability across
 * distributed ASF services and telemetry pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Enable end-to-end request tracing
 * - Improve forensic incident investigation
 * - Support distributed correlation chains
 * - Standardize observability identifiers
 * - Reduce ambiguity in multi-service flows
 *
 * DESIGN PRINCIPLES:
 * - Deterministic ID propagation
 * - Lightweight generation fallback
 * - Header-first resolution strategy
 * - Immutable request identity context
 * - Zero overhead execution path
 *
 * IMPORTANT:
 * Request IDs are NOT security credentials.
 *
 * NEVER:
 * - use request-id for authentication
 * - expose internal tracing topology
 * - rely on it for authorization decisions
 *
 * ============================================================
 */

import { Injectable, NestMiddleware } from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

import * as crypto from 'crypto';

/**
 * ============================================================
 * Request ID Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Ensure request ID existence
 * - Propagate correlation headers
 * - Standardize trace identifiers
 * ============================================================
 */

@Injectable()
export class RequestIdMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Middleware Entry Point
   * ============================================================
   */

  use(request: Request, response: Response, next: NextFunction): void {
    /**
     * ==========================================================
     * Header-Based Request ID Resolution
     * ==========================================================
     */

    let requestId = (request.headers['x-request-id'] as string) || '';

    const correlationId = (request.headers['x-correlation-id'] as string) || '';

    /**
     * ==========================================================
     * Fallback Generation Strategy
     * ==========================================================
     */

    if (!requestId) {
      requestId = this.generateRequestId();
    }

    /**
     * ==========================================================
     * Ensure Correlation Consistency
     * ==========================================================
     */

    const finalCorrelationId = correlationId || requestId;

    /**
     * ==========================================================
     * Attach to Request Context
     * ==========================================================
     */

    (request as any).requestContext = {
      ...(request as any).requestContext,

      requestId,

      correlationId: finalCorrelationId,

      receivedAt: Date.now(),
    };

    /**
     * ==========================================================
     * Propagate Downstream Headers
     * ==========================================================
     */

    response.setHeader('x-request-id', requestId);

    response.setHeader('x-correlation-id', finalCorrelationId);

    /**
     * ==========================================================
     * Continue Pipeline
     * ==========================================================
     */

    next();
  }

  /**
   * ============================================================
   * Deterministic Request ID Generator
   * ============================================================
   *
   * NOTE:
   * Uses cryptographic randomness to avoid collisions
   * under high-concurrency distributed workloads.
   * ============================================================
   */

  private generateRequestId(): string {
    const timestamp = Date.now();

    const random = crypto.randomBytes(8).toString('hex');

    return `req_${timestamp}_${random}`;
  }
}
