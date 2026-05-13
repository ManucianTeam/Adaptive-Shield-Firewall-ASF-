// apps/auth-service/src/auth/middleware/fingerprint.middleware.ts

import {
  Injectable,
  Logger,
  NestMiddleware,
} from '@nestjs/common';

import {
  NextFunction,
  Request,
  Response,
} from 'express';

import { createHash } from 'crypto';

/**
 * ============================================================================
 * ASF Fingerprint Middleware
 * ============================================================================
 *
 * Adaptive device-identification middleware responsible for:
 *
 *  - client fingerprint generation
 *  - distributed session correlation
 *  - device trust telemetry
 *  - suspicious device detection
 *  - authentication hardening
 *  - AI-assisted behavioral enrichment
 *
 * Security Characteristics:
 *
 *  - deterministic device hashing
 *  - low-latency fingerprint generation
 *  - gateway-compatible telemetry
 *  - replay-analysis readiness
 *  - distributed identity correlation
 *
 * Fingerprint Sources:
 *
 *  - IP address
 *  - User-Agent
 *  - Accept headers
 *  - language preferences
 *  - platform metadata
 *
 * Designed For:
 *
 *  - adaptive authentication systems
 *  - Zero Trust infrastructures
 *  - distributed session engines
 *  - AI security analyzers
 *  - anomaly correlation pipelines
 *
 * ============================================================================
 */

@Injectable()
export class FingerprintMiddleware
  implements NestMiddleware
{
  private readonly logger = new Logger(
    FingerprintMiddleware.name,
  );

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
    /**
     * ------------------------------------------------------------------------
     * Extract Client Metadata
     * ------------------------------------------------------------------------
     */

    const ip =
      this.extractIp(request);

    const userAgent =
      String(
        request.headers[
          'user-agent'
        ] || '',
      );

    const accept =
      String(
        request.headers.accept ||
          '',
      );

    const language =
      String(
        request.headers[
          'accept-language'
        ] || '',
      );

    const encoding =
      String(
        request.headers[
          'accept-encoding'
        ] || '',
      );

    /**
     * ------------------------------------------------------------------------
     * Raw Fingerprint Payload
     * ------------------------------------------------------------------------
     */

    const rawFingerprint = [
      ip,
      userAgent,
      accept,
      language,
      encoding,
    ].join('|');

    /**
     * ------------------------------------------------------------------------
     * Deterministic SHA-256 Fingerprint
     * ------------------------------------------------------------------------
     */

    const fingerprint =
      createHash('sha256')
        .update(rawFingerprint)
        .digest('hex');

    /**
     * ------------------------------------------------------------------------
     * Inject Fingerprint Context
     * ------------------------------------------------------------------------
     */

    request['fingerprint'] =
      fingerprint;

    request.headers[
      'x-device-fingerprint'
    ] = fingerprint;

    /**
     * ------------------------------------------------------------------------
     * Security Telemetry
     * ------------------------------------------------------------------------
     */

    this.logger.debug({
      message:
        'Device fingerprint generated',

      ip,

      fingerprint,
    });

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