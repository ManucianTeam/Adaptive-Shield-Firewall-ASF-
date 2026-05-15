/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Suspicious Activity Detection Guard
 * File: suspicious.guard.ts
 * ============================================================
 *
 * PURPOSE:
 * Detects and intercepts suspicious behavioral
 * patterns before requests reach protected
 * application resources.
 *
 * SECURITY OBJECTIVES:
 * - Detect anomalous request behavior
 * - Mitigate automated abuse traffic
 * - Prevent credential-stuffing attempts
 * - Reduce reconnaissance activity
 * - Generate adaptive threat telemetry
 * - Enforce behavioral trust boundaries
 *
 * DESIGN PRINCIPLES:
 * - Zero-trust request evaluation
 * - Lightweight behavioral analysis
 * - Deterministic enforcement flow
 * - Minimal latency overhead
 * - Structured observability
 *
 * IMPORTANT:
 * This guard should operate as a
 * lightweight pre-risk evaluation layer.
 *
 * Heavy operations MUST be delegated to:
 * - worker threads
 * - async telemetry processors
 * - external anomaly engines
 *
 * NEVER:
 * - block solely on one weak signal
 * - trust client-provided fingerprints
 * - expose scoring internals
 * - leak mitigation heuristics
 *
 * ============================================================
 */

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';

import { Request } from 'express';

/**
 * ============================================================
 * Suspicious Activity Detection Guard
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Behavioral anomaly detection
 * - Lightweight abuse mitigation
 * - Request telemetry generation
 * - Suspicious activity interception
 * ============================================================
 */

@Injectable()
export class SuspiciousGuard implements CanActivate {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(SuspiciousGuard.name);

  /**
   * ============================================================
   * Known Suspicious User-Agent Signatures
   * ============================================================
   *
   * NOTE:
   * This list should eventually move into:
   * - threat intelligence service
   * - Redis-backed dynamic signatures
   * - adaptive detection engine
   * ============================================================
   */

  private readonly suspiciousAgents = [
    'sqlmap',
    'curl',
    'wget',
    'python-requests',
    'axios',
    'postmanruntime',
    'go-http-client',
    'scanner',
    'masscan',
    'nmap',
  ];

  /**
   * ============================================================
   * Request Evaluation Entry Point
   * ============================================================
   */

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    /**
     * ==========================================================
     * Request Metadata Extraction
     * ==========================================================
     */

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const userAgent = String(request.headers['user-agent'] || '').toLowerCase();

    const requestPath = request.originalUrl;

    const method = request.method;

    /**
     * ==========================================================
     * Lightweight Suspicion Scoring
     * ==========================================================
     */

    let suspicionScore = 0;

    /**
     * ==========================================================
     * Suspicious User-Agent Detection
     * ==========================================================
     */

    const matchedAgent = this.suspiciousAgents.find((agent) =>
      userAgent.includes(agent),
    );

    if (matchedAgent) {
      suspicionScore += 40;
    }

    /**
     * ==========================================================
     * Path Reconnaissance Detection
     * ==========================================================
     */

    const suspiciousPaths = [
      '.env',
      'wp-admin',
      'phpmyadmin',
      'config',
      '.git',
      'actuator',
      'debug',
      'admin',
    ];

    const matchedPath = suspiciousPaths.find((path) =>
      requestPath.toLowerCase().includes(path),
    );

    if (matchedPath) {
      suspicionScore += 35;
    }

    /**
     * ==========================================================
     * Missing User-Agent Detection
     * ==========================================================
     */

    if (!userAgent) {
      suspicionScore += 20;
    }

    /**
     * ==========================================================
     * Method-Based Heuristic Evaluation
     * ==========================================================
     */

    if (['TRACE', 'CONNECT'].includes(method)) {
      suspicionScore += 50;
    }

    /**
     * ==========================================================
     * Adaptive Suspicion Threshold
     * ==========================================================
     */

    const suspicious = suspicionScore >= 50;

    /**
     * ==========================================================
     * Suspicious Request Handling
     * ==========================================================
     */

    if (suspicious) {
      /**
       * ========================================================
       * Threat Telemetry
       * ========================================================
       */

      this.logger.warn({
        event: 'SUSPICIOUS_ACTIVITY_DETECTED',

        suspicionScore,

        matchedAgent,

        matchedPath,

        ip,

        method,

        path: requestPath,

        userAgent,

        timestamp: Date.now(),
      });

      /**
       * ========================================================
       * Security Context Injection
       * ========================================================
       */

      (request as any).securityContext = {
        suspicious: true,

        suspicionScore,

        threatClassification: 'behavioral-anomaly',

        timestamp: Date.now(),
      };

      /**
       * ========================================================
       * Enforcement Decision
       * ========================================================
       *
       * NOTE:
       * Enterprise deployments may instead:
       * - challenge with CAPTCHA
       * - require MFA
       * - increase rate-limits
       * - shadow-ban requests
       * ========================================================
       */

      throw new ForbiddenException('Suspicious activity detected.');
    }

    /**
     * ==========================================================
     * Safe Request Telemetry
     * ==========================================================
     */

    this.logger.log({
      event: 'REQUEST_BEHAVIOR_ACCEPTED',

      suspicionScore,

      method,

      path: requestPath,

      timestamp: Date.now(),
    });

    return true;
  }
}
