/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Device Fingerprint Utility
 * File: fingerprint.util.ts
 * ============================================================
 *
 * PURPOSE:
 * Generates deterministic device and request
 * fingerprints for behavioral analysis,
 * session intelligence, and adaptive threat
 * correlation systems.
 *
 * This utility extracts:
 * - browser identity signals
 * - network indicators
 * - platform metadata
 * - behavioral headers
 * - entropy characteristics
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Support anomaly detection
 * - Improve replay resistance
 * - Strengthen session trust validation
 * - Enable distributed threat correlation
 * - Provide behavioral uniqueness heuristics
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Deterministic generation
 * - Lightweight computation
 * - Stateless execution
 * - Privacy-aware normalization
 * - Collision resistance
 *
 * ============================================================
 *
 * IMPORTANT:
 * Fingerprints are probabilistic identifiers.
 *
 * NEVER:
 * - treat fingerprints as unique identities
 * - rely solely on fingerprint stability
 * - store raw sensitive device attributes
 * - expose raw entropy vectors publicly
 *
 * ============================================================
 */

import { Request } from 'express';

import { createHash } from 'crypto';

/**
 * ============================================================
 * Fingerprint Entropy
 * ============================================================
 */

export interface FingerprintEntropy {
  headerEntropy: number;

  platformEntropy: number;

  localeEntropy: number;

  compositeEntropy: number;
}

/**
 * ============================================================
 * Fingerprint Behavior
 * ============================================================
 */

export interface FingerprintBehavior {
  requestVelocity: number;

  requestPatternScore: number;

  interactionScore: number;
}

/**
 * ============================================================
 * Fingerprint Network
 * ============================================================
 */

export interface FingerprintNetwork {
  ipAddress: string;

  forwardedFor?: string;

  protocol?: string;

  isDatacenter: boolean;
}

/**
 * ============================================================
 * Device Fingerprint
 * ============================================================
 */

export interface Fingerprint {
  fingerprintId: string;

  hash: string;

  userAgent: string;

  language: string;

  platform: string;

  timezone?: string;

  entropy: FingerprintEntropy;

  behavior: FingerprintBehavior;

  network: FingerprintNetwork;

  botProbability: number;

  replayRisk: number;

  createdAt: number;
}

/**
 * ============================================================
 * Fingerprint Utility
 * ============================================================
 */

export class FingerprintUtil {
  /**
   * ==========================================================
   * Generate Fingerprint
   * ==========================================================
   */

  static generate(request: Request): Fingerprint {
    /**
     * ========================================================
     * Header Extraction
     * ========================================================
     */

    const userAgent = request.headers['user-agent'] || 'unknown';

    const language = request.headers['accept-language'] || 'unknown';

    const platform = request.headers['sec-ch-ua-platform'] || 'unknown';

    const timezone = request.headers['x-timezone'] as string;

    const forwardedFor = request.headers['x-forwarded-for'] as string;

    const protocol = request.protocol;

    const ipAddress = request.ip || 'unknown';

    /**
     * ========================================================
     * Entropy Calculation
     * ========================================================
     */

    const entropy = this.calculateEntropy({
      userAgent,
      language,
      platform,
      timezone,
    });

    /**
     * ========================================================
     * Behavioral Heuristics
     * ========================================================
     */

    const behavior: FingerprintBehavior = {
      requestVelocity: this.extractVelocity(request),

      requestPatternScore: this.calculatePatternScore(request),

      interactionScore: this.calculateInteractionScore(request),
    };

    /**
     * ========================================================
     * Network Analysis
     * ========================================================
     */

    const network: FingerprintNetwork = {
      ipAddress,

      forwardedFor,

      protocol,

      isDatacenter: this.detectDatacenter(ipAddress),
    };

    /**
     * ========================================================
     * Composite Fingerprint Payload
     * ========================================================
     */

    const payload = [userAgent, language, platform, timezone, ipAddress].join(
      '|',
    );

    const hash = this.generateHash(payload);

    /**
     * ========================================================
     * Risk Heuristics
     * ========================================================
     */

    const botProbability = this.calculateBotProbability(
      userAgent,
      entropy,
      behavior,
    );

    const replayRisk = this.calculateReplayRisk(request);

    /**
     * ========================================================
     * Final Fingerprint
     * ========================================================
     */

    return {
      fingerprintId: hash.slice(0, 16),

      hash,

      userAgent,

      language,

      platform,

      timezone,

      entropy,

      behavior,

      network,

      botProbability,

      replayRisk,

      createdAt: Date.now(),
    };
  }

  /**
   * ==========================================================
   * Entropy Engine
   * ==========================================================
   */

  private static calculateEntropy(
    payload: Record<string, unknown>,
  ): FingerprintEntropy {
    const values = Object.values(payload);

    let score = 0;

    for (const value of values) {
      if (value && String(value).length > 5) {
        score += 1;
      }
    }

    const headerEntropy = score / values.length;

    const platformEntropy = payload.platform ? 0.8 : 0.2;

    const localeEntropy = payload.language ? 0.7 : 0.1;

    const compositeEntropy =
      (headerEntropy + platformEntropy + localeEntropy) / 3;

    return {
      headerEntropy,

      platformEntropy,

      localeEntropy,

      compositeEntropy,
    };
  }

  /**
   * ==========================================================
   * Velocity Heuristic
   * ==========================================================
   */

  private static extractVelocity(request: Request): number {
    /**
     * ========================================================
     * Placeholder Heuristic
     * ========================================================
     *
     * Production:
     * - Redis counters
     * - Sliding windows
     * - Token buckets
     * ========================================================
     */

    const velocityHeader = request.headers['x-request-velocity'];

    return Number(velocityHeader || 0);
  }

  /**
   * ==========================================================
   * Pattern Score
   * ==========================================================
   */

  private static calculatePatternScore(request: Request): number {
    const path = request.originalUrl || '';

    const suspiciousPatterns = [
      '/wp-admin',

      '/.env',

      '/phpmyadmin',

      '/admin',

      '/config',
    ];

    for (const pattern of suspiciousPatterns) {
      if (path.includes(pattern)) {
        return 0.9;
      }
    }

    return 0.2;
  }

  /**
   * ==========================================================
   * Interaction Score
   * ==========================================================
   */

  private static calculateInteractionScore(request: Request): number {
    const contentLength = Number(request.headers['content-length'] || 0);

    /**
     * ========================================================
     * Simplified Heuristic
     * ========================================================
     */

    if (contentLength > 0) {
      return 0.8;
    }

    return 0.3;
  }

  /**
   * ==========================================================
   * Datacenter Detection
   * ==========================================================
   */

  private static detectDatacenter(ip: string): boolean {
    /**
     * ========================================================
     * Placeholder Logic
     * ========================================================
     *
     * Production:
     * - ASN intelligence feeds
     * - IP reputation DB
     * - MaxMind / IP2ASN
     * ========================================================
     */

    const knownPrefixes = ['34.', '35.', '52.', '54.', '104.'];

    return knownPrefixes.some((prefix) => ip.startsWith(prefix));
  }

  /**
   * ==========================================================
   * Bot Probability Engine
   * ==========================================================
   */

  private static calculateBotProbability(
    userAgent: string,

    entropy: FingerprintEntropy,

    behavior: FingerprintBehavior,
  ): number {
    let score = 0;

    /**
     * ========================================================
     * Headless Browser Detection
     * ========================================================
     */

    const suspiciousAgents = [
      'HeadlessChrome',

      'PhantomJS',

      'curl',

      'wget',

      'python-requests',
    ];

    for (const agent of suspiciousAgents) {
      if (userAgent.includes(agent)) {
        score += 0.4;
      }
    }

    /**
     * ========================================================
     * Low Entropy Heuristic
     * ========================================================
     */

    if (entropy.compositeEntropy < 0.4) {
      score += 0.2;
    }

    /**
     * ========================================================
     * Velocity Heuristic
     * ========================================================
     */

    if (behavior.requestVelocity > 25) {
      score += 0.3;
    }

    return Math.min(1, score);
  }

  /**
   * ==========================================================
   * Replay Risk Engine
   * ==========================================================
   */

  private static calculateReplayRisk(request: Request): number {
    const replayHeader = request.headers['x-replay-risk'];

    if (!replayHeader) {
      return 0.1;
    }

    return Math.min(1, Number(replayHeader));
  }

  /**
   * ==========================================================
   * SHA256 Hash Generator
   * ==========================================================
   */

  private static generateHash(payload: string): string {
    return createHash('sha256').update(payload).digest('hex');
  }
}
