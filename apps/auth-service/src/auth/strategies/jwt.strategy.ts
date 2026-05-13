// apps/auth-service/src/auth/strategies/jwt.strategy.ts

import {
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';

import { PassportStrategy } from '@nestjs/passport';

import { ExtractJwt, Strategy } from 'passport-jwt';

import { ConfigService } from '@nestjs/config';

import { Request } from 'express';

import { JwtPayload } from '../interfaces/jwt-payload.interface';

import { SessionService } from '../services/session.service';

/**
 * ============================================================================
 * ASF JWT Access Strategy
 * ============================================================================
 *
 * Enterprise-grade JWT authentication strategy engineered for distributed
 * Zero Trust infrastructures and adaptive identity-validation pipelines.
 *
 * Core Responsibilities:
 *
 *  - access-token extraction
 *  - cryptographic JWT validation
 *  - distributed session correlation
 *  - replay mitigation
 *  - adaptive trust propagation
 *  - runtime identity hydration
 *
 * Security Architecture:
 *
 *  - Bearer-token authentication
 *  - stateless identity validation
 *  - Redis-backed session correlation
 *  - distributed access verification
 *  - session revocation awareness
 *  - fingerprint-aware authentication flow
 *
 * Designed For:
 *
 *  - API gateways
 *  - distributed microservices
 *  - adaptive security systems
 *  - AI-assisted threat analysis
 *  - enterprise authentication infrastructures
 *
 * ============================================================================
 */

@Injectable()
export class JwtStrategy extends PassportStrategy(
  Strategy,
  'jwt',
)
{
  private readonly logger = new Logger(
    JwtStrategy.name,
  );

  constructor(
    private readonly configService: ConfigService,

    private readonly sessionService: SessionService,
  ) {
    super({
      /**
       * ----------------------------------------------------------------------
       * JWT Extraction Strategy
       * ----------------------------------------------------------------------
       */

      jwtFromRequest:
        ExtractJwt.fromAuthHeaderAsBearerToken(),

      /**
       * ----------------------------------------------------------------------
       * Expiration Enforcement
       * ----------------------------------------------------------------------
       */

      ignoreExpiration:
        false,

      /**
       * ----------------------------------------------------------------------
       * Access Token Secret
       * ----------------------------------------------------------------------
       */

      secretOrKey:
        configService.get<string>(
          'JWT_ACCESS_SECRET',
        ),

      /**
       * ----------------------------------------------------------------------
       * Request Injection
       * ----------------------------------------------------------------------
       */

      passReqToCallback:
        true,
    });
  }

  /**
   * --------------------------------------------------------------------------
   * Distributed JWT Validation Pipeline
   * --------------------------------------------------------------------------
   */

  async validate(
    request: Request,
    payload: JwtPayload,
  ): Promise<JwtPayload> {
    /**
     * ------------------------------------------------------------------------
     * Session Presence Validation
     * ------------------------------------------------------------------------
     */

    if (!payload.sessionId) {
      throw new UnauthorizedException(
        'Missing session context',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Distributed Session Correlation
     * ------------------------------------------------------------------------
     */

    const session =
      await this.sessionService.findById(
        payload.sessionId,
      );

    if (!session) {
      this.logger.warn({
        event:
          'jwt_session_not_found',

        sessionId:
          payload.sessionId,
      });

      throw new UnauthorizedException(
        'Session is invalid or expired',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Session Revocation Enforcement
     * ------------------------------------------------------------------------
     */

    if (
      session.status ===
      'revoked'
    ) {
      this.logger.warn({
        event:
          'revoked_session_access_attempt',

        sessionId:
          payload.sessionId,
      });

      throw new UnauthorizedException(
        'Session revoked',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Fingerprint Correlation
     * ------------------------------------------------------------------------
     */

    const requestFingerprint =
      request.headers[
        'x-device-fingerprint'
      ] as string;

    if (
      payload.fingerprint &&
      requestFingerprint &&
      payload.fingerprint !==
        requestFingerprint
    ) {
      this.logger.warn({
        event:
          'fingerprint_mismatch',

        sessionId:
          payload.sessionId,
      });

      throw new UnauthorizedException(
        'Device fingerprint mismatch',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Session Activity Refresh
     * ------------------------------------------------------------------------
     */

    await this.sessionService.touch(
      payload.sessionId,
    );

    /**
     * ------------------------------------------------------------------------
     * Adaptive Security Telemetry
     * ------------------------------------------------------------------------
     */

    this.logger.debug({
      event:
        'jwt_authenticated',

      userId:
        payload.sub,

      sessionId:
        payload.sessionId,

      trustLevel:
        payload.trustLevel,
    });

    /**
     * ------------------------------------------------------------------------
     * Runtime Identity Projection
     * ------------------------------------------------------------------------
     */

    return {
      ...payload,

      sessionStatus:
        session.status,

      trustLevel:
        session.trustScore,

      riskScore:
        session.riskScore,
    };
  }
}