// apps/gateway/src/utils/entropy.util.ts

import crypto from 'crypto';
import { IncomingHttpHeaders } from 'http';

/**
 * =========================================================
 * Adaptive Shield Firewall (ASF)
 * Entropy / Fingerprint Utility
 * =========================================================
 *
 * PURPOSE:
 * - Generate high-entropy browser/device fingerprints
 * - Detect bots / spoofed browsers / headless automation
 * - Behavioral anomaly analysis
 * - Risk engine enrichment
 *
 * SECURITY NOTES:
 * - NEVER trust a single entropy source
 * - Fingerprints are probabilistic, NOT identity proof
 * - Always combine with:
 *    - rate limiting
 *    - behavioral scoring
 *    - TLS fingerprinting
 *    - IP reputation
 *    - session analysis
 *
 * PRO FEATURES:
 * - Stable hashing
 * - Header-order fingerprinting
 * - Entropy scoring
 * - Suspicion heuristics
 * - Normalized payloads
 *
 * =========================================================
 */

export interface EntropyPayload {
  ip?: string;

  userAgent?: string;
  language?: string;

  timezone?: string;

  screenWidth?: number;
  screenHeight?: number;
  colorDepth?: number;
  pixelRatio?: number;

  canvasHash?: string;

  webglVendor?: string;
  webglRenderer?: string;

  platform?: string;
  cpuCores?: number;
  deviceMemory?: number;

  fonts?: string[];

  headerOrder?: string[];

  tlsJa3?: string;

  cookiesEnabled?: boolean;
  touchSupport?: boolean;
}

export interface EntropyAnalysis {
  fingerprint: string;

  entropyScore: number;

  suspicious: boolean;

  riskFactors: string[];

  normalized: Record<string, unknown>;
}

export class EntropyUtil {
  /**
   * =========================================================
   * NORMALIZATION
   * =========================================================
   */

  static normalize(payload: EntropyPayload): Record<string, unknown> {
    return {
      ip: payload.ip || 'unknown',

      userAgent: payload.userAgent || 'unknown',
      language: payload.language || 'unknown',

      timezone: payload.timezone || 'unknown',

      screen: {
        width: payload.screenWidth || 0,
        height: payload.screenHeight || 0,
        colorDepth: payload.colorDepth || 0,
        pixelRatio: payload.pixelRatio || 1,
      },

      canvasHash: payload.canvasHash || 'unknown',

      webgl: {
        vendor: payload.webglVendor || 'unknown',
        renderer: payload.webglRenderer || 'unknown',
      },

      hardware: {
        platform: payload.platform || 'unknown',
        cpuCores: payload.cpuCores || 0,
        deviceMemory: payload.deviceMemory || 0,
      },

      fonts: [...(payload.fonts || [])].sort(),

      headerOrder: payload.headerOrder || [],

      tlsJa3: payload.tlsJa3 || 'unknown',

      cookiesEnabled: payload.cookiesEnabled ?? false,

      touchSupport: payload.touchSupport ?? false,
    };
  }

  /**
   * =========================================================
   * STABLE JSON
   * Prevent hash variance
   * =========================================================
   */

  static stableStringify(obj: unknown): string {
    return JSON.stringify(obj, Object.keys(obj as object).sort());
  }

  /**
   * =========================================================
   * FINGERPRINT GENERATION
   * =========================================================
   */

  static generateFingerprint(payload: EntropyPayload): string {
    const normalized = this.normalize(payload);

    const stable = this.stableStringify(normalized);

    return crypto.createHash('sha256').update(stable).digest('hex');
  }

  /**
   * =========================================================
   * HEADER ORDER EXTRACTION
   * =========================================================
   *
   * WHY IMPORTANT:
   * Different browsers send headers differently.
   *
   * Chrome:
   * host
   * connection
   * sec-ch-ua
   * user-agent
   * accept
   *
   * Headless bots often fail to replicate this correctly.
   */

  static extractHeaderOrder(headers: IncomingHttpHeaders): string[] {
    return Object.keys(headers).map((h) => h.toLowerCase());
  }

  /**
   * =========================================================
   * ENTROPY SCORING
   * =========================================================
   *
   * Higher score = stronger uniqueness
   *
   * 0-30   => weak
   * 31-60  => medium
   * 61-100 => strong
   */

  static calculateEntropyScore(payload: EntropyPayload): number {
    let score = 0;

    if (payload.canvasHash) score += 25;

    if (payload.webglVendor && payload.webglRenderer) {
      score += 20;
    }

    if (payload.headerOrder?.length) {
      score += 15;
    }

    if (payload.fonts?.length) {
      score += 15;
    }

    if (payload.screenWidth && payload.screenHeight) {
      score += 10;
    }

    if (payload.timezone) {
      score += 5;
    }

    if (payload.platform) {
      score += 5;
    }

    if (payload.tlsJa3) {
      score += 20;
    }

    return Math.min(score, 100);
  }

  /**
   * =========================================================
   * BOT / SPOOF DETECTION
   * =========================================================
   */

  static analyzeSuspicion(payload: EntropyPayload): {
    suspicious: boolean;
    riskFactors: string[];
  } {
    const riskFactors: string[] = [];

    const ua = payload.userAgent?.toLowerCase() || '';

    /**
     * Headless browser indicators
     */
    if (
      ua.includes('headless') ||
      ua.includes('phantom') ||
      ua.includes('selenium')
    ) {
      riskFactors.push('Headless/automation user-agent detected');
    }

    /**
     * Missing canvas fingerprint
     */
    if (!payload.canvasHash) {
      riskFactors.push('Missing canvas fingerprint');
    }

    /**
     * Fake screen sizes
     */
    if (payload.screenWidth === 0 || payload.screenHeight === 0) {
      riskFactors.push('Invalid screen resolution');
    }

    /**
     * Suspicious timezone
     */
    if (!payload.timezone) {
      riskFactors.push('Missing timezone');
    }

    /**
     * Missing WebGL
     */
    if (!payload.webglRenderer) {
      riskFactors.push('Missing WebGL renderer');
    }

    /**
     * Header order anomalies
     */
    if (payload.headerOrder && payload.headerOrder.length < 3) {
      riskFactors.push('Abnormal header order');
    }

    /**
     * Automation hardware fingerprints
     */
    if (payload.cpuCores === 0 || payload.deviceMemory === 0) {
      riskFactors.push('Suspicious hardware entropy');
    }

    return {
      suspicious: riskFactors.length >= 3,
      riskFactors,
    };
  }

  /**
   * =========================================================
   * COMPLETE ANALYSIS
   * =========================================================
   */

  static analyze(payload: EntropyPayload): EntropyAnalysis {
    const normalized = this.normalize(payload);

    const fingerprint = this.generateFingerprint(payload);

    const entropyScore = this.calculateEntropyScore(payload);

    const suspicion = this.analyzeSuspicion(payload);

    return {
      fingerprint,
      entropyScore,

      suspicious: suspicion.suspicious,

      riskFactors: suspicion.riskFactors,

      normalized,
    };
  }
}
