/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Adaptive Rate Limiting Middleware
 * File: rate-limit.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Enforces per-client request rate constraints to
 * mitigate abuse, flooding, and automated traffic spikes.
 *
 * SECURITY OBJECTIVES:
 * - Prevent DDoS-style request flooding
 * - Reduce brute-force authentication attempts
 * - Limit API abuse and scraping behavior
 * - Stabilize system under load pressure
 * - Support adaptive traffic shaping
 *
 * DESIGN PRINCIPLES:
 * - Lightweight in-memory fast path
 * - Deterministic token-bucket model
 * - Fail-safe conservative enforcement
 * - Minimal request latency overhead
 * - Optional distributed backend extension
 *
 * IMPORTANT:
 * This implementation is NODE-LOCAL ONLY.
 * Production MUST use:
 * - Redis sliding window / token bucket
 * - distributed rate-limit coordinator
 * - edge gateway enforcement (NGINX / WAF)
 *
 * NEVER:
 * - rely solely on in-memory counters in clusters
 * - ignore burst traffic patterns
 * - expose internal rate-limit logic to clients
 *
 * ============================================================
 */

import {
  Injectable,
  Logger,
  NestMiddleware,
  TooManyRequestsException,
} from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

/**
 * ============================================================
 * Rate Limit Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Request rate enforcement
 * - Client traffic shaping
 * - Burst protection
 * - Abuse mitigation
 * ============================================================
 */

@Injectable()
export class RateLimitMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Structured Logger
   * ============================================================
   */

  private readonly logger = new Logger(RateLimitMiddleware.name);

  /**
   * ============================================================
   * In-Memory Rate Store (Node-Local)
   * ============================================================
   */

  private readonly requests = new Map<string, number[]>();

  /**
   * ============================================================
   * Rate Limits Configuration
   * ============================================================
   *
   * Example policy:
   * - 60 requests per 60 seconds per IP
   * ============================================================
   */

  private readonly WINDOW_MS = 60_000;

  private readonly MAX_REQUESTS = 60;

  /**
   * ============================================================
   * Middleware Entry Point
   * ============================================================
   */

  use(request: Request, response: Response, next: NextFunction): void {
    /**
     * ==========================================================
     * Client Identity Resolution
     * ==========================================================
     */

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const now = Date.now();

    /**
     * ==========================================================
     * Request History Retrieval
     * ==========================================================
     */

    const timestamps = this.requests.get(ip) || [];

    /**
     * ==========================================================
     * Sliding Window Cleanup
     * ==========================================================
     */

    const filtered = timestamps.filter((ts) => now - ts < this.WINDOW_MS);

    /**
     * ==========================================================
     * Rate Check Evaluation
     * ==========================================================
     */

    if (filtered.length >= this.MAX_REQUESTS) {
      this.logger.warn({
        event: 'RATE_LIMIT_EXCEEDED',

        ip,

        requestCount: filtered.length,

        windowMs: this.WINDOW_MS,

        timestamp: now,
      });

      throw new TooManyRequestsException(
        'Rate limit exceeded. Please slow down.',
      );
    }

    /**
     * ==========================================================
     * Record Request
     * ==========================================================
     */

    filtered.push(now);

    this.requests.set(ip, filtered);

    /**
     * ==========================================================
     * Attach Context
     * ==========================================================
     */

    (request as any).rateLimitContext = {
      ip,

      requestsInWindow: filtered.length,

      maxRequests: this.MAX_REQUESTS,

      windowMs: this.WINDOW_MS,
    };

    /**
     * ==========================================================
     * Continue Pipeline
     * ==========================================================
     */

    next();
  }
}
