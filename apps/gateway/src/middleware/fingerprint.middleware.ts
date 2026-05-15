/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Behavioral Fingerprint Middleware
 * File: fingerprint.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Generates a lightweight behavioral fingerprint
 * for each incoming request and attaches it to
 * the request execution context for downstream
 * security, telemetry, and anomaly pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Establish request behavioral continuity
 * - Enable probabilistic identity modeling
 * - Support replay detection pipelines
 * - Enrich threat intelligence signals
 * - Improve distributed correlation accuracy
 *
 * DESIGN PRINCIPLES:
 * - Deterministic fingerprint construction
 * - Low-latency feature extraction
 * - Minimal request interference
 * - Non-invasive context enrichment
 * - Zero-trust identity modeling
 *
 * IMPORTANT:
 * Fingerprints are probabilistic signals only.
 *
 * NEVER:
 * - treat fingerprint as authentication
 * - trust client-provided identifiers
 * - persist raw sensitive headers unfiltered
 * - block requests based solely on fingerprint
 *
 * ============================================================
 */

import { Injectable, Logger, NestMiddleware } from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

import * as crypto from 'crypto';

/**
 * ============================================================
 * Behavioral Fingerprint Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Extract request features
 * - Generate deterministic fingerprint ID
 * - Attach security context
 * - Emit lightweight telemetry
 * ============================================================
 */

@Injectable()
export class FingerprintMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Structured Logger
   * ============================================================
   */

  private readonly logger = new Logger(FingerprintMiddleware.name);

  /**
   * ============================================================
   * Middleware Entry Point
   * ============================================================
   */

  use(request: Request, response: Response, next: NextFunction): void {
    /**
     * ==========================================================
     * Request Metadata Extraction
     * ==========================================================
     */

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const userAgent = String(request.headers['user-agent'] || '').toLowerCase();

    const acceptLanguage = String(request.headers['accept-language'] || '');

    const acceptEncoding = String(request.headers['accept-encoding'] || '');

    const method = request.method;

    const path = request.originalUrl;

    const referer = String(request.headers['referer'] || '');

    const origin = String(request.headers['origin'] || '');

    /**
     * ==========================================================
     * Feature Vector Construction
     * ==========================================================
     *
     * NOTE:
     * This is a simplified deterministic model.
     * Enterprise deployments should enrich this with:
     * - JA3/JA4 TLS fingerprints
     * - device canvas entropy
     * - ASN reputation scoring
     * - behavioral time-series embeddings
     * ==========================================================
     */

    const rawFingerprint = [
      ip,
      userAgent,
      acceptLanguage,
      acceptEncoding,
      method,
      path,
      referer,
      origin,
    ].join('|');

    /**
     * ==========================================================
     * Deterministic Hash Generation
     * ==========================================================
     */

    const fingerprintId = crypto
      .createHash('sha256')
      .update(rawFingerprint)
      .digest('hex');

    /**
     * ==========================================================
     * Lightweight Entropy Signals
     * ==========================================================
     */

    const headerCount = Object.keys(request.headers).length;

    const entropyEstimate = this.calculateSimpleEntropy(rawFingerprint);

    /**
     * ==========================================================
     * Fingerprint Object Construction
     * ==========================================================
     */

    const fingerprint = {
      id: fingerprintId,

      ipAddress: ip,

      userAgent,

      acceptLanguage,

      acceptEncoding,

      requestMethod: method,

      requestPath: path,

      referer,

      origin,

      timestamp: Date.now(),

      headers: {
        'header-count': String(headerCount),
      },

      entropy: {
        compositeEntropy: entropyEstimate,
      },
    };

    /**
     * ==========================================================
     * Attach to Request Context
     * ==========================================================
     */

    (request as any).fingerprint = fingerprint;

    /**
     * ==========================================================
     * Lightweight Telemetry
     * ==========================================================
     */

    this.logger.log({
      event: 'FINGERPRINT_GENERATED',

      fingerprintId,

      ip,

      path,

      method,

      headerCount,

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
   * Simple Entropy Estimation Function
   * ============================================================
   *
   * NOTE:
   * This is NOT cryptographically accurate entropy.
   * It is only a lightweight heuristic signal.
   * ============================================================
   */

  private calculateSimpleEntropy(input: string): number {
    const frequency: Record<string, number> = {};

    for (const char of input) {
      frequency[char] = (frequency[char] || 0) + 1;
    }

    let entropy = 0;

    const length = input.length || 1;

    for (const key in frequency) {
      const p = frequency[key] / length;

      entropy -= p * Math.log2(p);
    }

    return Number(entropy.toFixed(4));
  }
}
