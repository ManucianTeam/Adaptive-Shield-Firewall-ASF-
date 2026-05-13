// apps/auth-service/src/auth/strategies/refresh.strategy.ts

import {
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';

import { PassportStrategy } from '@nestjs/passport';

import { ExtractJwt, Strategy } from 'passport-jwt';

import { ConfigService } from '@nestjs/config';

import { Request } from 'express';

import { SessionService } from '../services/session.service';

/**
 * ============================================================================
 * ASF Refresh Token Strategy
 * ============================================================================
 *
 * Enterprise-grade refresh-token authentication strategy engineered for
 * distributed Zero Trust identity systems and adaptive session infrastructures.
 *
 * Core Responsibilities:
 *
 *  - refresh-token extraction
 *  - refresh-session correlation
 *  - replay-attack mitigation
 *  - token rotation validation
 *  - distributed session continuity
 *  - adaptive identity revalidation
 *
 * Security Architecture:
 *
 *  - signed refresh-token validation
 *  - Redis-backed session verification
 *  - hashed refresh-token persistence
 *  - fingerprint-aware reauthentication
 *  - stateless JWT lifecycle management
 *  - distributed trust enforcement
 *
 * Designed For:
 *
 *  - adaptive authentication systems
 *  - enterprise IAM infrastructures
 *  - distributed API gateways
 *  - microservice security fabrics
 *  - AI-assisted access control
 *
 * ============================================================================
 */

@Injectable()
export class RefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
)
{
  private readonly logger = new Logger(
    RefreshStrategy.name,
  );

  constructor(
    private readonly configService: ConfigService,

    private readonly sessionService: SessionService,
  ) {
    super({
      /**
       * ----------------------------------------------------------------------
       * Refresh Token Extraction
       * ----------------------------------------------------------------------
       */

      jwtFromRequest:
        ExtractJwt.fromExtractors([
          (
            request: Request,
          ) => {
            /**
             * --------------------------------------------------------------
             * Cookie-Based Extraction
             * --------------------------------------------------------------
             */

            if (
              request?.cookies
                ?.refreshToken
            ) {
              return request.cookies
                .refreshToken;
            }

            /**
             * --------------------------------------------------------------
             * Authorization Header Fallback
             * --------------------------------------------------------------
             */

            const auth =
              request?.headers
                ?.authorization;

            if (
              auth &&
              auth.startsWith(
                'Bearer ',
              )
            ) {
              return auth.replace(
                'Bearer ',
                '',
              );
            }

            return null;
          },
        ]),

      /**
       * ----------------------------------------------------------------------
       * Expiration Enforcement
       * ----------------------------------------------------------------------
       */

      ignoreExpiration:
        false,

      /**
       * ----------------------------------------------------------------------
       * Refresh Token Secret
       * ----------------------------------------------------------------------
       */

      secretOrKey:
        configService.get<string>(
          'JWT_REFRESH_SECRET',
        ),

      /**
       * ----------------------------------------------------------------------
       * Request Context Injection
       * ----------------------------------------------------------------------
       */

      passReqToCallback:
        true,
    });
  }

  /**
   * --------------------------------------------------------------------------
   * Refresh Token Validation Pipeline
   * --------------------------------------------------------------------------
   */

  async validate(
    request: Request,
    payload: any,
  ): Promise<any> {
    /**
     * ------------------------------------------------------------------------
     * Token-Type Enforcement
     * ------------------------------------------------------------------------
     */

    if (
      payload.type !==
      'refresh'
    ) {
      throw new UnauthorizedException(
        'Invalid refresh token type',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Session Correlation
     * ------------------------------------------------------------------------
     */

    const session =
      await this.sessionService.findById(
        payload.sessionId,
      );

    if (!session) {
      this.logger.warn({
        event:
          'refresh_session_not_found',

        sessionId:
          payload.sessionId,
      });

      throw new UnauthorizedException(
        'Session not found',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Revocation Enforcement
     * ------------------------------------------------------------------------
     */

    if (
      session.status ===
      'revoked'
    ) {
      this.logger.warn({
        event:
          'revoked_refresh_attempt',

        sessionId:
          payload.sessionId,
      });

      throw new UnauthorizedException(
        'Session revoked',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Refresh Token Extraction
     * ------------------------------------------------------------------------
     */

    const refreshToken =
      this.extractToken(
        request,
      );

    if (!refreshToken) {
      throw new UnauthorizedException(
        'Missing refresh token',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Replay-Resistant Token Validation
     * ------------------------------------------------------------------------
     */

    const valid =
      await this.sessionService
        .validateRefreshToken(
          payload.sessionId,
          refreshToken,
        );

    if (!valid) {
      this.logger.warn({
        event:
          'refresh_token_validation_failed',

        sessionId:
          payload.sessionId,
      });

      throw new UnauthorizedException(
        'Invalid refresh token',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Device Fingerprint Validation
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
          'refresh_fingerprint_mismatch',

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
        'refresh_authenticated',

      userId:
        payload.sub,

      sessionId:
        payload.sessionId,
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

  /**
   * --------------------------------------------------------------------------
   * Refresh Token Extraction Utility
   * --------------------------------------------------------------------------
   */

  private extractToken(
    request: Request,
  ): string | null {
    /**
     * ------------------------------------------------------------------------
     * Cookie Source
     * ------------------------------------------------------------------------
     */

    if (
      request?.cookies
        ?.refreshToken
    ) {
      return request.cookies
        .refreshToken;
    }

    /**
     * ------------------------------------------------------------------------
     * Authorization Header Source
     * ------------------------------------------------------------------------
     */

    const auth =
      request?.headers
        ?.authorization;

    if (
      auth &&
      auth.startsWith(
        'Bearer ',
      )
    ) {
      return auth.replace(
        'Bearer ',
        '',
      );
    }

    return null;
  }
}