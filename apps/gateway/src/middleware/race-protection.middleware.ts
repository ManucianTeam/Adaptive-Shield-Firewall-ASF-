/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Distributed Race Condition Protection Middleware
 * File: race-protection.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides lightweight protection against race-condition
 * exploitation patterns at the gateway/middleware layer,
 * primarily for high-concurrency sensitive endpoints.
 *
 * SECURITY OBJECTIVES:
 * - Prevent double-spend / double-execution flows
 * - Reduce concurrent state corruption risk
 * - Detect abnormal parallel request bursts
 * - Support idempotency enforcement
 * - Strengthen transactional integrity
 *
 * DESIGN PRINCIPLES:
 * - Deterministic idempotency keys
 * - Lightweight concurrency tracking
 * - Non-blocking fast-path execution
 * - Redis-compatible distributed locking model
 * - Fail-safe conservative blocking strategy
 *
 * IMPORTANT:
 * This middleware is a FIRST-LAYER defense only.
 * MUST be paired with:
 * - database constraints
 * - transactional isolation levels
 * - idempotency enforcement at service layer
 *
 * NEVER:
 * - rely solely on in-memory locking in distributed systems
 * - assume request order consistency
 * - ignore lock expiration safety
 *
 * ============================================================
 */

import {
  Injectable,
  Logger,
  NestMiddleware,
  ConflictException,
} from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

/**
 * ============================================================
 * Race Protection Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Idempotency enforcement
 * - Concurrent request detection
 * - Lightweight race mitigation
 * - Transaction safety pre-check
 * ============================================================
 */

@Injectable()
export class RaceProtectionMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Structured Logger
   * ============================================================
   */

  private readonly logger = new Logger(RaceProtectionMiddleware.name);

  /**
   * ============================================================
   * In-Memory Lock Registry (Single Node Only)
   * ============================================================
   *
   * NOTE:
   * This is NOT safe for distributed environments.
   * Replace with Redis SET NX / Redlock pattern.
   * ============================================================
   */

  private readonly activeLocks = new Map<string, number>();

  /**
   * ============================================================
   * Lock TTL (ms)
   * ============================================================
   */

  private readonly LOCK_TTL_MS = 5000;

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

    const method = request.method;

    const path = request.originalUrl;

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    /**
     * ==========================================================
     * Idempotency Key Resolution
     * ==========================================================
     *
     * Prefer explicit client-provided key,
     * fallback to deterministic hash-like key.
     * ==========================================================
     */

    const idempotencyKey =
      (request.headers['idempotency-key'] as string) ||
      this.generateFallbackKey(method, path, ip);

    const now = Date.now();

    /**
     * ==========================================================
     * Lock Cleanup (TTL-based)
     * ==========================================================
     */

    this.cleanupExpiredLocks(now);

    /**
     * ==========================================================
     * Concurrent Execution Check
     * ==========================================================
     */

    if (this.activeLocks.has(idempotencyKey)) {
      this.logger.warn({
        event: 'RACE_CONDITION_BLOCKED',

        idempotencyKey,

        method,

        path,

        ip,

        timestamp: now,
      });

      throw new ConflictException('Concurrent request detected. Please retry.');
    }

    /**
     * ==========================================================
     * Acquire Lock
     * ==========================================================
     */

    this.activeLocks.set(idempotencyKey, now);

    /**
     * ==========================================================
     * Attach Context
     * ==========================================================
     */

    (request as any).raceContext = {
      idempotencyKey,

      lockedAt: now,

      ttl: this.LOCK_TTL_MS,
    };

    /**
     * ==========================================================
     * Response Hook (Release Lock)
     * ==========================================================
     */

    response.on('finish', () => {
      this.activeLocks.delete(idempotencyKey);
    });

    response.on('close', () => {
      this.activeLocks.delete(idempotencyKey);
    });

    /**
     * ==========================================================
     * Continue Pipeline
     * ==========================================================
     */

    next();
  }

  /**
   * ============================================================
   * TTL Cleanup Strategy
   * ============================================================
   */

  private cleanupExpiredLocks(now: number): void {
    for (const [key, timestamp] of this.activeLocks.entries()) {
      if (now - timestamp > this.LOCK_TTL_MS) {
        this.activeLocks.delete(key);
      }
    }
  }

  /**
   * ============================================================
   * Fallback Idempotency Key Generator
   * ============================================================
   */

  private generateFallbackKey(
    method: string,
    path: string,
    ip: string,
  ): string {
    return `lock_${method}_${path}_${ip}`;
  }
}
