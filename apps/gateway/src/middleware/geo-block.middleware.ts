/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Geo-Blocking Middleware
 * File: geo-block.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Performs lightweight geolocation-based access
 * control to reduce exposure from high-risk or
 * policy-restricted regions.
 *
 * SECURITY OBJECTIVES:
 * - Enforce geo-fencing policies
 * - Reduce attack surface exposure
 * - Mitigate distributed abuse sources
 * - Support compliance-driven restrictions
 * - Enable adaptive regional blocking
 *
 * DESIGN PRINCIPLES:
 * - Early request rejection (edge-layer)
 * - Minimal latency overhead
 * - Deterministic allow/deny rules
 * - Configurable policy boundaries
 * - Transparent observability logging
 *
 * IMPORTANT:
 * Geo-blocking is a weak signal alone.
 * MUST be combined with:
 * - behavioral fingerprinting
 * - bot detection
 * - risk scoring engine
 *
 * NEVER:
 * - rely solely on IP geolocation accuracy
 * - block without fallback policy reasoning
 * - expose internal geo-intelligence sources
 *
 * ============================================================
 */

import {
  Injectable,
  Logger,
  NestMiddleware,
  ForbiddenException,
} from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

/**
 * ============================================================
 * Geo-Blocking Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Region-based access filtering
 * - Policy enforcement
 * - Security telemetry generation
 * ============================================================
 */

@Injectable()
export class GeoBlockMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Structured Logger
   * ============================================================
   */

  private readonly logger = new Logger(GeoBlockMiddleware.name);

  /**
   * ============================================================
   * Blocked Regions List
   * ============================================================
   *
   * NOTE:
   * In production systems, this SHOULD be replaced by:
   * - dynamic threat intelligence feeds
   * - ASN reputation scoring
   * - adaptive policy engine
   * - Redis-backed geo policy cache
   * ============================================================
   */

  private readonly blockedCountries = new Set<string>([
    // Example policy list (replace with real compliance rules)
    'xx', // placeholder
    'yy',
  ]);

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

    const path = request.originalUrl;

    const method = request.method;

    /**
     * ==========================================================
     * Geo Resolution (Placeholder Layer)
     * ==========================================================
     *
     * NOTE:
     * Replace with real provider:
     * - MaxMind GeoIP2
     * - Cloudflare IP Intelligence
     * - AWS WAF GeoMatch
     * ==========================================================
     */

    const geo = this.resolveGeoFromIp(ip);

    const country = geo?.country || 'unknown';

    /**
     * ==========================================================
     * Policy Evaluation
     * ==========================================================
     */

    const isBlocked = this.blockedCountries.has(country.toLowerCase());

    /**
     * ==========================================================
     * Blocking Decision
     * ==========================================================
     */

    if (isBlocked) {
      this.logger.warn({
        event: 'GEO_BLOCK_TRIGGERED',

        ip,

        country,

        path,

        method,

        timestamp: Date.now(),
      });

      throw new ForbiddenException('Access denied by geographic policy.');
    }

    /**
     * ==========================================================
     * Security Context Enrichment
     * ==========================================================
     */

    (request as any).geoContext = {
      ip,

      country,

      region: geo?.region || null,

      city: geo?.city || null,

      blocked: false,

      evaluatedAt: Date.now(),
    };

    /**
     * ==========================================================
     * Telemetry Logging
     * ==========================================================
     */

    this.logger.log({
      event: 'GEO_POLICY_PASSED',

      ip,

      country,

      path,

      method,

      timestamp: Date.now(),
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
   * IP → Geo Resolver (Mock Layer)
   * ============================================================
   *
   * NOTE:
   * Replace with production-grade GeoIP service.
   * ============================================================
   */

  private resolveGeoFromIp(ip: string): {
    country?: string;
    region?: string;
    city?: string;
  } | null {
    /**
     * Simulated deterministic fallback behavior
     * (for development only)
     */

    if (!ip || ip === 'unknown') {
      return null;
    }

    return {
      country: 'local',
      region: 'dev-region',
      city: 'dev-city',
    };
  }
}
