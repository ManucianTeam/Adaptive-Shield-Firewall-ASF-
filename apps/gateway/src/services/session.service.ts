/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Secure Session Intelligence Service
 * File: session.service.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides distributed session lifecycle management,
 * behavioral session intelligence, and adaptive
 * security telemetry for authenticated entities.
 *
 * This service is responsible for:
 * - secure session creation
 * - session validation
 * - adaptive trust tracking
 * - distributed session storage
 * - replay detection support
 * - behavioral session telemetry
 * - session revocation
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Prevent session hijacking
 * - Detect anomalous session mutations
 * - Support zero-trust architectures
 * - Enable adaptive risk enforcement
 * - Reduce replay attack surfaces
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Stateless application layer
 * - Distributed Redis-backed storage
 * - Deterministic validation logic
 * - Minimal latency overhead
 * - Horizontally scalable
 *
 * ============================================================
 *
 * IMPORTANT:
 * Sessions represent probabilistic trust states.
 *
 * NEVER:
 * - permanently trust active sessions
 * - expose internal session identifiers
 * - store sensitive credentials in sessions
 * - assume client integrity
 *
 * ============================================================
 */

import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';

import Redis from 'ioredis';

import { createHash, randomBytes } from 'crypto';

import { Request } from 'express';

/**
 * ============================================================
 * Session Entity
 * ============================================================
 */

export interface SessionEntity {
  sessionId: string;

  userId: string;

  fingerprintHash: string;

  ipAddress: string;

  userAgent: string;

  createdAt: number;

  updatedAt: number;

  expiresAt: number;

  trustScore: number;

  revoked: boolean;

  metadata?: Record<string, unknown>;
}

/**
 * ============================================================
 * Session Validation Result
 * ============================================================
 */

export interface SessionValidationResult {
  valid: boolean;

  session?: SessionEntity;

  riskDetected: boolean;

  indicators: string[];
}

/**
 * ============================================================
 * Session Service
 * ============================================================
 */

@Injectable()
export class SessionService {
  /**
   * ==========================================================
   * Logger
   * ==========================================================
   */

  private readonly logger = new Logger(SessionService.name);

  /**
   * ==========================================================
   * Redis Client
   * ==========================================================
   */

  private readonly redis: Redis;

  /**
   * ==========================================================
   * Session Configuration
   * ==========================================================
   */

  private readonly SESSION_TTL = 60 * 60 * 24 * 7; // 7 days

  private readonly SESSION_PREFIX = 'asf:session';

  /**
   * ==========================================================
   * Constructor
   * ==========================================================
   */

  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',

      port: Number(process.env.REDIS_PORT || 6379),

      password: process.env.REDIS_PASSWORD,

      lazyConnect: true,
    });

    this.redis.on('connect', () => {
      this.logger.log('🧠 Session intelligence engine connected');
    });

    this.redis.on('error', (error) => {
      this.logger.error('Redis session error', error);
    });
  }

  /**
   * ==========================================================
   * Create Secure Session
   * ==========================================================
   */

  async createSession(
    userId: string,

    request: Request,

    metadata?: Record<string, unknown>,
  ): Promise<SessionEntity> {
    const sessionId = this.generateSessionId();

    const now = Date.now();

    const expiresAt = now + this.SESSION_TTL * 1000;

    const fingerprintHash = this.generateFingerprintHash(request);

    const session: SessionEntity = {
      sessionId,

      userId,

      fingerprintHash,

      ipAddress: request.ip || 'unknown',

      userAgent: request.headers['user-agent'] || 'unknown',

      createdAt: now,

      updatedAt: now,

      expiresAt,

      trustScore: 1,

      revoked: false,

      metadata,
    };

    /**
     * ========================================================
     * Persist Session
     * ========================================================
     */

    await this.redis.set(
      this.buildSessionKey(sessionId),

      JSON.stringify(session),

      'EX',

      this.SESSION_TTL,
    );

    /**
     * ========================================================
     * Telemetry
     * ========================================================
     */

    this.logger.log({
      event: 'SESSION_CREATED',

      sessionId,

      userId,

      ipAddress: session.ipAddress,

      timestamp: now,
    });

    return session;
  }

  /**
   * ==========================================================
   * Validate Session
   * ==========================================================
   */

  async validateSession(
    sessionId: string,

    request: Request,
  ): Promise<SessionValidationResult> {
    const indicators: string[] = [];

    const session = await this.getSession(sessionId);

    /**
     * ========================================================
     * Missing Session
     * ========================================================
     */

    if (!session) {
      return {
        valid: false,

        riskDetected: true,

        indicators: ['SESSION_NOT_FOUND'],
      };
    }

    /**
     * ========================================================
     * Revoked Session
     * ========================================================
     */

    if (session.revoked) {
      return {
        valid: false,

        riskDetected: true,

        indicators: ['SESSION_REVOKED'],
      };
    }

    /**
     * ========================================================
     * Expired Session
     * ========================================================
     */

    if (Date.now() > session.expiresAt) {
      return {
        valid: false,

        riskDetected: true,

        indicators: ['SESSION_EXPIRED'],
      };
    }

    /**
     * ========================================================
     * Fingerprint Validation
     * ========================================================
     */

    const currentFingerprint = this.generateFingerprintHash(request);

    let riskDetected = false;

    if (currentFingerprint !== session.fingerprintHash) {
      indicators.push('FINGERPRINT_MISMATCH');

      riskDetected = true;

      session.trustScore -= 0.3;
    }

    /**
     * ========================================================
     * IP Mutation Detection
     * ========================================================
     */

    if (request.ip !== session.ipAddress) {
      indicators.push('IP_ADDRESS_CHANGED');

      riskDetected = true;

      session.trustScore -= 0.15;
    }

    /**
     * ========================================================
     * User-Agent Mutation
     * ========================================================
     */

    const currentUA = request.headers['user-agent'] || 'unknown';

    if (currentUA !== session.userAgent) {
      indicators.push('USER_AGENT_CHANGED');

      riskDetected = true;

      session.trustScore -= 0.1;
    }

    /**
     * ========================================================
     * Clamp Trust Score
     * ========================================================
     */

    session.trustScore = Math.max(0, Math.min(1, session.trustScore));

    /**
     * ========================================================
     * Auto Revocation
     * ========================================================
     */

    if (session.trustScore < 0.2) {
      session.revoked = true;

      indicators.push('SESSION_AUTO_REVOKED');
    }

    /**
     * ========================================================
     * Refresh Session Activity
     * ========================================================
     */

    session.updatedAt = Date.now();

    await this.persistSession(session);

    /**
     * ========================================================
     * Telemetry
     * ========================================================
     */

    this.logger.warn({
      event: 'SESSION_VALIDATION',

      sessionId,

      userId: session.userId,

      trustScore: session.trustScore,

      riskDetected,

      indicators,

      timestamp: Date.now(),
    });

    return {
      valid: !session.revoked,

      session,

      riskDetected,

      indicators,
    };
  }

  /**
   * ==========================================================
   * Revoke Session
   * ==========================================================
   */

  async revokeSession(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);

    if (!session) {
      return;
    }

    session.revoked = true;

    await this.persistSession(session);

    this.logger.warn({
      event: 'SESSION_REVOKED',

      sessionId,

      userId: session.userId,

      timestamp: Date.now(),
    });
  }

  /**
   * ==========================================================
   * Require Valid Session
   * ==========================================================
   */

  async requireValidSession(
    sessionId: string,

    request: Request,
  ): Promise<SessionEntity> {
    const validation = await this.validateSession(sessionId, request);

    if (!validation.valid) {
      throw new UnauthorizedException('Invalid session');
    }

    return validation.session!;
  }

  /**
   * ==========================================================
   * Retrieve Session
   * ==========================================================
   */

  async getSession(sessionId: string): Promise<SessionEntity | null> {
    const raw = await this.redis.get(this.buildSessionKey(sessionId));

    if (!raw) {
      return null;
    }

    return JSON.parse(raw);
  }

  /**
   * ==========================================================
   * Persist Session
   * ==========================================================
   */

  private async persistSession(session: SessionEntity): Promise<void> {
    await this.redis.set(
      this.buildSessionKey(session.sessionId),

      JSON.stringify(session),

      'EX',

      this.SESSION_TTL,
    );
  }

  /**
   * ==========================================================
   * Generate Session ID
   * ==========================================================
   */

  private generateSessionId(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * ==========================================================
   * Generate Fingerprint Hash
   * ==========================================================
   */

  private generateFingerprintHash(request: Request): string {
    const payload = [
      request.ip,

      request.headers['user-agent'],

      request.headers['accept-language'],

      request.headers['sec-ch-ua'],
    ].join('|');

    return createHash('sha256').update(payload).digest('hex');
  }

  /**
   * ==========================================================
   * Session Key Builder
   * ==========================================================
   */

  private buildSessionKey(sessionId: string): string {
    return `${this.SESSION_PREFIX}:${sessionId}`;
  }
}
