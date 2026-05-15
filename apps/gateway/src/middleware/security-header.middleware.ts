/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Security Header Enforcement Middleware
 * File: security-header.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Enforces baseline HTTP security headers to reduce
 * client-side attack surface and strengthen browser
 * security posture at the gateway layer.
 *
 * SECURITY OBJECTIVES:
 * - Prevent MIME sniffing attacks
 * - Reduce XSS exploitation surface
 * - Enforce transport security policies
 * - Harden browser execution context
 * - Improve compliance baseline (OWASP aligned)
 *
 * DESIGN PRINCIPLES:
 * - Early response hardening
 * - Deterministic header injection
 * - Zero dependency execution path
 * - Minimal latency overhead
 * - Conservative secure defaults
 *
 * IMPORTANT:
 * Security headers are NOT sufficient alone.
 * MUST be combined with:
 * - CSP at edge/CDN layer
 * - input validation
 * - output encoding
 * - authentication hardening
 *
 * NEVER:
 * - expose internal infrastructure headers
 * - override upstream CDN security policies blindly
 * - leak versioning or runtime metadata
 *
 * ============================================================
 */

import { Injectable, NestMiddleware } from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

/**
 * ============================================================
 * Security Header Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Inject security headers
 * - Harden browser execution context
 * - Standardize HTTP security posture
 * ============================================================
 */

@Injectable()
export class SecurityHeaderMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Middleware Entry Point
   * ============================================================
   */

  use(request: Request, response: Response, next: NextFunction): void {
    /**
     * ==========================================================
     * Content Security Baseline
     * ==========================================================
     */

    response.setHeader('X-Content-Type-Options', 'nosniff');

    response.setHeader('X-Frame-Options', 'DENY');

    response.setHeader('X-XSS-Protection', '0');

    /**
     * ==========================================================
     * Transport Security Policy
     * ==========================================================
     */

    response.setHeader(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains',
    );

    /**
     * ==========================================================
     * Referrer Policy
     * ==========================================================
     */

    response.setHeader('Referrer-Policy', 'no-referrer');

    /**
     * ==========================================================
     * Permissions Policy (Feature Restriction)
     * ==========================================================
     */

    response.setHeader(
      'Permissions-Policy',
      'geolocation=(), microphone=(), camera=()',
    );

    /**
     * ==========================================================
     * Content Security Policy (Basic Hardened Profile)
     * ==========================================================
     *
     * NOTE:
     * Production SHOULD dynamically generate CSP
     * based on service requirements.
     * ==========================================================
     */

    response.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    );

    /**
     * ==========================================================
     * Remove Server Fingerprinting
     * ==========================================================
     */

    response.removeHeader('X-Powered-By');

    /**
     * ==========================================================
     * Continue Pipeline
     * ==========================================================
     */

    next();
  }
}
