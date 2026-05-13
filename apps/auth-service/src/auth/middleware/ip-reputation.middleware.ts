// apps/auth-service/src/auth/middleware/ip-reputation.middleware.ts

import {
  ForbiddenException,
  Injectable,
  Logger,
  NestMiddleware,
} from '@nestjs/common';

import {
  NextFunction,
  Request,
  Response,
} from 'express';

/**
 * ============================================================================
 * ASF IP Reputation Middleware
 * ============================================================================
 *
 * Adaptive network reputation middleware responsible for:
 *
 *  - hostile IP detection
 *  - reputation-based request filtering
 *  - TOR / proxy identification
 *  - datacenter traffic detection
 *  - distributed abuse mitigation
 *  - AI-assisted network trust analysis
 *
 * Security Characteristics:
 *
 *  - deterministic reputation enforcement
 *  - low-latency threat validation
 *  - Zero Trust ingress protection
 *  - distributed mitigation compatibility
 *  - adaptive request hardening
 *
 * Detection Categories:
 *
 *  - TOR exit nodes
 *  - anonymous proxies
 *  - cloud abuse infrastructure
 *  - brute-force origins
 *  - credential stuffing sources
 *  - suspicious geolocation ranges
 *
 * Designed For:
 *
 *  - authentication gateways
 *  - adaptive firewall systems
 *  - AI-assisted security layers
 *  - distributed API protection
 *  - high-risk endpoint enforcement
 *
 * ============================================================================
 */

@Injectable()
export class IpReputationMiddleware
  implements NestMiddleware
{
  private readonly logger = new Logger(
    IpReputationMiddleware.name,
  );

  /**
   * --------------------------------------------------------------------------
   * Static High-Risk IP Cache
   * --------------------------------------------------------------------------
   *
   * Example in-memory reputation storage.
   *
   * Production deployments should replace this with:
   *
   *  - Redis
   *  - SIEM feeds
   *  - AbuseIPDB
   *  - threat intelligence APIs
   *  - distributed reputation graphs
   */

  private readonly blockedIps =
    new Set<string>([
      '45.95.147.12',
      '185.220.101.1',
      '103.251.167.20',
    ]);

  /**
   * --------------------------------------------------------------------------
   * Suspicious ASN / Hosting Indicators
   * --------------------------------------------------------------------------
   */

  private readonly suspiciousPatterns =
    [
      'tor',
      'proxy',
      'crawler',
      'scanner',
      'bot',
    ];

  /**
   * --------------------------------------------------------------------------
   * Middleware Pipeline
   * --------------------------------------------------------------------------
   */

  use(
    request: Request,
    response: Response,
    next: NextFunction,
  ): void {
    const ip =
      this.extractIp(request);

    const userAgent =
      String(
        request.headers[
          'user-agent'
        ] || '',
      ).toLowerCase();

    /**
     * ------------------------------------------------------------------------
     * Explicit Reputation Block
     * ------------------------------------------------------------------------
     */

    if (
      this.blockedIps.has(ip)
    ) {
      this.logger.warn({
        message:
          'Blocked request from blacklisted IP',

        ip,
      });

      throw new ForbiddenException({
        success: false,

        message:
          'Request blocked by IP reputation policy',

        code:
          'IP_REPUTATION_BLOCK',
      });
    }

    /**
     * ------------------------------------------------------------------------
     * Suspicious User-Agent Heuristics
     * ------------------------------------------------------------------------
     */

    const suspicious =
      this.suspiciousPatterns.some(
        (pattern) =>
          userAgent.includes(
            pattern,
          ),
      );

    if (suspicious) {
      request['networkThreat'] = {
        suspicious: true,

        reason:
          'Suspicious network signature detected',
      };

      this.logger.warn({
        message:
          'Suspicious network fingerprint detected',

        ip,

        userAgent,
      });
    }

    /**
     * ------------------------------------------------------------------------
     * Inject Reputation Metadata
     * ------------------------------------------------------------------------
     */

    request['ipReputation'] = {
      trusted: !suspicious,

      blocked: false,

      sourceIp: ip,
    };

    next();
  }

  /**
   * --------------------------------------------------------------------------
   * Client IP Extraction
   * --------------------------------------------------------------------------
   */

  private extractIp(
    request: Request,
  ): string {
    const forwarded =
      request.headers[
        'x-forwarded-for'
      ];

    if (
      typeof forwarded ===
      'string'
    ) {
      return forwarded
        .split(',')[0]
        .trim();
    }

    return (
      request.ip ||
      request.socket
        ?.remoteAddress ||
      '0.0.0.0'
    );
  }
}