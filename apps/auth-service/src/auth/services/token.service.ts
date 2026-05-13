// apps/auth-service/src/auth/services/token.service.ts

import {
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';

import { JwtService } from '@nestjs/jwt';

import { randomUUID } from 'crypto';

import { JwtPayload } from '../interfaces/jwt-payload.interface';

/**
 * ============================================================================
 * ASF Token Service
 * ============================================================================
 *
 * Enterprise-grade JWT orchestration service engineered for distributed
 * authentication infrastructures and adaptive Zero Trust identity systems.
 *
 * Core Responsibilities:
 *
 *  - access-token generation
 *  - refresh-token generation
 *  - JWT validation
 *  - distributed identity propagation
 *  - replay-resistant token rotation
 *  - cryptographic session correlation
 *
 * Security Architecture:
 *
 *  - stateless access-token model
 *  - signed refresh-token lifecycle
 *  - deterministic token claims
 *  - cryptographic integrity enforcement
 *  - adaptive trust metadata propagation
 *  - distributed gateway compatibility
 *
 * Designed For:
 *
 *  - microservice ecosystems
 *  - adaptive authentication systems
 *  - Zero Trust infrastructures
 *  - distributed API gateways
 *  - AI-assisted access-control pipelines
 *
 * Integrated With:
 *
 *  - JwtStrategy
 *  - RefreshStrategy
 *  - SessionService
 *  - Redis-backed session engines
 *  - distributed security middleware
 *
 * ============================================================================
 */

@Injectable()
export class TokenService
{
  private readonly logger = new Logger(
    TokenService.name,
  );

  /**
   * --------------------------------------------------------------------------
   * Access Token Expiration
   * --------------------------------------------------------------------------
   */

  private readonly ACCESS_TOKEN_TTL =
    '15m';

  /**
   * --------------------------------------------------------------------------
   * Refresh Token Expiration
   * --------------------------------------------------------------------------
   */

  private readonly REFRESH_TOKEN_TTL =
    '7d';

  constructor(
    private readonly jwtService: JwtService,
  ) {}

  /**
   * --------------------------------------------------------------------------
   * Distributed Token Generation Pipeline
   * --------------------------------------------------------------------------
   */

  async generateTokens(
    payload: JwtPayload,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    /**
     * ------------------------------------------------------------------------
     * Access Token Claims
     * ------------------------------------------------------------------------
     */

    const accessPayload: JwtPayload = {
      ...payload,

      jti:
        randomUUID(),

      trustLevel:
        payload.trustLevel ?? 100,

      iat:
        Math.floor(
          Date.now() / 1000,
        ),
    };

    /**
     * ------------------------------------------------------------------------
     * Refresh Token Claims
     * ------------------------------------------------------------------------
     */

    const refreshPayload = {
      sub:
        payload.sub,

      email:
        payload.email,

      roles:
        payload.roles,

      sessionId:
        payload.sessionId,

      fingerprint:
        payload.fingerprint,

      type:
        'refresh',

      jti:
        randomUUID(),
    };

    /**
     * ------------------------------------------------------------------------
     * Parallel JWT Signing
     * ------------------------------------------------------------------------
     */

    const [
      accessToken,
      refreshToken,
    ] = await Promise.all([
      this.jwtService.signAsync(
        accessPayload,
        {
          expiresIn:
            this.ACCESS_TOKEN_TTL,
        },
      ),

      this.jwtService.signAsync(
        refreshPayload,
        {
          expiresIn:
            this.REFRESH_TOKEN_TTL,
        },
      ),
    ]);

    this.logger.log({
      event:
        'jwt_pair_generated',

      sessionId:
        payload.sessionId,

      subject:
        payload.sub,
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Access Token Verification
   * --------------------------------------------------------------------------
   */

  async verifyAccessToken(
    token: string,
  ): Promise<JwtPayload> {
    try {
      const payload =
        await this.jwtService.verifyAsync<JwtPayload>(
          token,
        );

      /**
       * ----------------------------------------------------------------------
       * Refresh Token Misuse Protection
       * ----------------------------------------------------------------------
       */

      if (
        (payload as any)
          .type ===
        'refresh'
      ) {
        throw new UnauthorizedException(
          'Invalid access token type',
        );
      }

      return payload;
    } catch (error) {
      this.logger.warn({
        event:
          'access_token_verification_failed',
      });

      throw new UnauthorizedException(
        'Invalid access token',
      );
    }
  }

  /**
   * --------------------------------------------------------------------------
   * Refresh Token Verification
   * --------------------------------------------------------------------------
   */

  async verifyRefreshToken(
    token: string,
  ): Promise<any> {
    try {
      const payload =
        await this.jwtService.verifyAsync(
          token,
        );

      /**
       * ----------------------------------------------------------------------
       * Token-Type Enforcement
       * ----------------------------------------------------------------------
       */

      if (
        payload.type !==
        'refresh'
      ) {
        throw new UnauthorizedException(
          'Invalid refresh token type',
        );
      }

      return payload;
    } catch (error) {
      this.logger.warn({
        event:
          'refresh_token_verification_failed',
      });

      throw new UnauthorizedException(
        'Invalid refresh token',
      );
    }
  }

  /**
   * --------------------------------------------------------------------------
   * Stateless Token Decoding
   * --------------------------------------------------------------------------
   */

  decode(
    token: string,
  ): JwtPayload | null {
    try {
      return this.jwtService.decode(
        token,
      ) as JwtPayload;
    } catch {
      return null;
    }
  }

  /**
   * --------------------------------------------------------------------------
   * Token Expiration Introspection
   * --------------------------------------------------------------------------
   */

  isExpired(
    payload: JwtPayload,
  ): boolean {
    if (!payload.exp) {
      return true;
    }

    return (
      payload.exp <
      Math.floor(
        Date.now() / 1000,
      )
    );
  }

  /**
   * --------------------------------------------------------------------------
   * Remaining Token Lifetime
   * --------------------------------------------------------------------------
   */

  remainingLifetime(
    payload: JwtPayload,
  ): number {
    if (!payload.exp) {
      return 0;
    }

    return Math.max(
      payload.exp -
        Math.floor(
          Date.now() / 1000,
        ),
      0,
    );
  }

  /**
   * --------------------------------------------------------------------------
   * JWT Correlation Metadata
   * --------------------------------------------------------------------------
   */

  buildTokenMetadata(
    payload: JwtPayload,
  ) {
    return {
      subject:
        payload.sub,

      sessionId:
        payload.sessionId,

      fingerprint:
        payload.fingerprint,

      trustLevel:
        payload.trustLevel,

      riskScore:
        payload.riskScore,

      expiresAt:
        payload.exp,
    };
  }
}