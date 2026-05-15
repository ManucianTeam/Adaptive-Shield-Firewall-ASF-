/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Behavioral Bot Detection Middleware
 * File: bot-detection.middleware.ts
 * ============================================================
 *
 * PURPOSE:
 * Performs lightweight behavioral bot detection
 * and automated traffic classification before
 * requests enter protected ASF pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Detect automated traffic patterns
 * - Reduce credential-stuffing attempts
 * - Mitigate reconnaissance activity
 * - Prevent scraping abuse
 * - Support adaptive threat scoring
 * - Enrich behavioral telemetry
 *
 * DESIGN PRINCIPLES:
 * - Low-latency request evaluation
 * - Deterministic execution flow
 * - Lightweight heuristic analysis
 * - Minimal event-loop impact
 * - Structured observability
 *
 * IMPORTANT:
 * This middleware is intended as an
 * early-stage behavioral detection layer.
 *
 * Heavy anomaly analysis SHOULD be delegated to:
 * - worker-thread pipelines
 * - async AI scoring services
 * - distributed telemetry processors
 *
 * NEVER:
 * - block solely on one weak signal
 * - trust client-provided fingerprints
 * - expose detection heuristics
 * - synchronously persist telemetry
 *
 * ============================================================
 */

import { Injectable, Logger, NestMiddleware } from '@nestjs/common';

import { NextFunction, Request, Response } from 'express';

/**
 * ============================================================
 * Behavioral Bot Detection Middleware
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Automated traffic classification
 * - Lightweight heuristic analysis
 * - Threat telemetry generation
 * - Behavioral signal enrichment
 * ============================================================
 */

@Injectable()
export class BotDetectionMiddleware implements NestMiddleware {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(BotDetectionMiddleware.name);

  /**
   * ============================================================
   * Suspicious User-Agent Signatures
   * ============================================================
   *
   * NOTE:
   * Enterprise deployments SHOULD migrate
   * these signatures into:
   * - Redis-backed intelligence stores
   * - adaptive detection engines
   * - real-time reputation feeds
   * ============================================================
   */

  private readonly suspiciousAgents = [
    'curl',
    'wget',
    'python-requests',
    'axios',
    'scrapy',
    'headless',
    'phantomjs',
    'selenium',
    'playwright',
    'puppeteer',
    'postmanruntime',
    'go-http-client',
    'masscan',
    'sqlmap',
    'nmap',
  ];

  /**
   * ============================================================
   * Middleware Execution Entry Point
   * ============================================================
   */

  use(request: Request, response: Response, next: NextFunction): void {
    /**
     * ==========================================================
     * Request Metadata Extraction
     * ==========================================================
     */

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const method = request.method;

    const path = request.originalUrl;

    const userAgent = String(request.headers['user-agent'] || '').toLowerCase();

    /**
     * ==========================================================
     * Behavioral Risk Initialization
     * ==========================================================
     */

    let botProbability = 0;

    let suspiciousSignals: string[] = [];

    /**
     * ==========================================================
     * Missing User-Agent Detection
     * ==========================================================
     */

    if (!userAgent) {
      botProbability += 25;

      suspiciousSignals.push('missing-user-agent');
    }

    /**
     * ==========================================================
     * Suspicious Agent Signature Detection
     * ==========================================================
     */

    const matchedAgent = this.suspiciousAgents.find((agent) =>
      userAgent.includes(agent),
    );

    if (matchedAgent) {
      botProbability += 45;

      suspiciousSignals.push(`signature:${matchedAgent}`);
    }

    /**
     * ==========================================================
     * Header Entropy Heuristics
     * ==========================================================
     *
     * Extremely small header sets may indicate:
     * - primitive automation
     * - scraping clients
     * - reconnaissance tooling
     * ==========================================================
     */

    const headerCount = Object.keys(request.headers).length;

    if (headerCount <= 4) {
      botProbability += 20;

      suspiciousSignals.push('low-header-entropy');
    }

    /**
     * ==========================================================
     * Suspicious Method Evaluation
     * ==========================================================
     */

    if (['TRACE', 'CONNECT'].includes(method)) {
      botProbability += 40;

      suspiciousSignals.push('unsafe-http-method');
    }

    /**
     * ==========================================================
     * Lightweight Automation Classification
     * ==========================================================
     */

    const suspicious = botProbability >= 50;

    /**
     * ==========================================================
     * Request Security Context Injection
     * ==========================================================
     */

    (request as any).securityContext = {
      ...(request as any).securityContext,

      suspicious,

      botProbability,

      suspiciousSignals,

      threatClassification: suspicious ? 'automated-traffic' : 'normal-traffic',

      analyzedAt: Date.now(),
    };

    /**
     * ==========================================================
     * Structured Threat Telemetry
     * ==========================================================
     */

    if (suspicious) {
      this.logger.warn({
        event: 'SUSPICIOUS_BOT_ACTIVITY',

        botProbability,

        suspiciousSignals,

        ip,

        method,

        path,

        userAgent,

        timestamp: Date.now(),
      });
    } else {
      this.logger.log({
        event: 'TRAFFIC_BEHAVIOR_ANALYZED',

        botProbability,

        path,

        method,

        timestamp: Date.now(),
      });
    }

    /**
     * ==========================================================
     * Adaptive Enforcement Extensions
     * ==========================================================
     *
     * FUTURE EXTENSIONS:
     * - CAPTCHA challenge orchestration
     * - dynamic rate-limit escalation
     * - reputation-based scoring
     * - distributed trust correlation
     * - AI anomaly enrichment
     * ==========================================================
     */

    next();
  }
}
