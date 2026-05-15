/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Authentication Authorization Guard
 * File: auth.guard.ts
 * ============================================================
 *
 * PURPOSE:
 * Enforces authenticated access validation for
 * protected ASF endpoints and security-sensitive
 * request pipelines.
 *
 * SECURITY OBJECTIVES:
 * - Validate access-token authenticity
 * - Enforce session integrity
 * - Prevent unauthorized access
 * - Detect token abuse patterns
 * - Support behavioral telemetry generation
 * - Protect downstream service boundaries
 *
 * DESIGN PRINCIPLES:
 * - Zero-trust request validation
 * - Stateless authentication enforcement
 * - Deterministic authorization flow
 * - Minimal information disclosure
 * - Lightweight request-path execution
 *
 * IMPORTANT:
 * NEVER:
 * - trust unsigned JWT payloads
 * - expose token internals
 * - leak validation failure reasons
 * - log raw access tokens
 *
 * RECOMMENDED:
 * - short-lived access tokens
 * - refresh-token rotation
 * - behavioral risk correlation
 * - token replay protection
 * - distributed revocation support
 *
 * ============================================================
 */

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';

import { JwtService } from '@nestjs/jwt';

import { ConfigService } from '@nestjs/config';

import { Request } from 'express';

/**
 * ============================================================
 * Authentication Authorization Guard
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Access-token verification
 * - Session identity enforcement
 * - Security telemetry generation
 * - Request identity injection
 * ============================================================
 */

@Injectable()
export class AuthGuard implements CanActivate {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private readonly jwtService: JwtService,

    private readonly configService: ConfigService,
  ) {}

  /**
   * ============================================================
   * Guard Execution Entry Point
   * ============================================================
   */

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    /**
     * ==========================================================
     * Authorization Header Extraction
     * ==========================================================
     */

    const authorizationHeader = request.headers['authorization'];

    /**
     * ==========================================================
     * Bearer Token Validation
     * ==========================================================
     */

    if (
      !authorizationHeader ||
      typeof authorizationHeader !== 'string' ||
      !authorizationHeader.startsWith('Bearer ')
    ) {
      this.logger.warn({
        event: 'AUTH_TOKEN_MISSING',

        path: request.originalUrl,

        method: request.method,

        ip: request.ip || request.socket?.remoteAddress,

        timestamp: Date.now(),
      });

      throw new UnauthorizedException('Authentication required.');
    }

    /**
     * ==========================================================
     * Access Token Extraction
     * ==========================================================
     */

    const accessToken = authorizationHeader.replace('Bearer ', '');

    /**
     * ==========================================================
     * JWT Secret Resolution
     * ==========================================================
     */

    const jwtSecret = this.configService.get<string>('JWT_SECRET');

    if (!jwtSecret) {
      this.logger.error({
        event: 'JWT_CONFIGURATION_ERROR',

        reason: 'JWT_SECRET configuration missing.',

        timestamp: Date.now(),
      });

      throw new UnauthorizedException('Authentication unavailable.');
    }

    try {
      /**
       * ========================================================
       * Token Verification
       * ========================================================
       *
       * SECURITY:
       * - Signature validation
       * - Expiration validation
       * - Tamper detection
       * ========================================================
       */

      const payload = await this.jwtService.verifyAsync(accessToken, {
        secret: jwtSecret,
      });

      /**
       * ========================================================
       * Lightweight Identity Injection
       * ========================================================
       *
       * Inject validated identity metadata
       * for downstream request pipelines.
       * ========================================================
       */

      (request as any).user = {
        id: payload.sub,

        email: payload.email,

        role: payload.role,

        sessionId: payload.sessionId,

        tokenVersion: payload.tokenVersion,

        authenticated: true,
      };

      /**
       * ========================================================
       * Authentication Telemetry
       * ========================================================
       */

      this.logger.log({
        event: 'AUTHENTICATION_SUCCESS',

        userId: payload.sub,

        role: payload.role,

        path: request.originalUrl,

        method: request.method,

        timestamp: Date.now(),
      });

      return true;
    } catch (error) {
      /**
       * ========================================================
       * Failed Authentication Handling
       * ========================================================
       *
       * POSSIBLE CAUSES:
       * - expired token
       * - invalid signature
       * - tampered token
       * - malformed JWT
       * - replayed credential
       * ========================================================
       */

      this.logger.warn({
        event: 'AUTHENTICATION_FAILED',

        path: request.originalUrl,

        method: request.method,

        ip: request.ip || request.socket?.remoteAddress,

        userAgent: request.headers['user-agent'],

        timestamp: Date.now(),
      });

      throw new UnauthorizedException('Invalid authentication credentials.');
    }
  }
}
