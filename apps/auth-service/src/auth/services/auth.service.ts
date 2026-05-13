// apps/auth-service/src/auth/services/auth.service.ts

import {
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';

import * as bcrypt from 'bcrypt';

import { UsersService } from '../../users/services/users.service';

import { TokenService } from './token.service';
import { SessionService } from './session.service';
import { PasswordService } from './password.service';

import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { RefreshTokenDto } from '../dto/refresh-token.dto';

import { RiskScoreService } from '../../ai-security/services/risk-score.service';

import { LoginAttemptEvent } from '../events/login-attempt.event';
import { SuspiciousLoginEvent } from '../events/suspicious-login.event';

import { SessionInterface } from '../interfaces/session.interface';

/**
 * ============================================================================
 * ASF Authentication Service
 * ============================================================================
 *
 * Enterprise-grade adaptive authentication orchestration service engineered
 * for distributed Zero Trust infrastructures and AI-assisted security systems.
 *
 * Core Responsibilities:
 *
 *  - credential validation
 *  - JWT issuance
 *  - refresh-token rotation
 *  - distributed session orchestration
 *  - adaptive risk validation
 *  - suspicious-login mitigation
 *  - identity lifecycle management
 *
 * Security Architecture:
 *
 *  - stateless access-token model
 *  - distributed Redis-backed sessions
 *  - replay-resistant refresh rotation
 *  - adaptive trust scoring
 *  - AI-assisted anomaly enforcement
 *  - behavioral threat mitigation
 *
 * Integrated With:
 *
 *  - JwtStrategy
 *  - RefreshStrategy
 *  - SuspiciousGuard
 *  - Redis session storage
 *  - AI security analyzers
 *  - distributed API gateways
 *
 * ============================================================================
 */

@Injectable()
export class AuthService
{
  private readonly logger = new Logger(
    AuthService.name,
  );

  constructor(
    private readonly usersService: UsersService,

    private readonly tokenService: TokenService,

    private readonly sessionService: SessionService,

    private readonly passwordService: PasswordService,

    private readonly riskScoreService: RiskScoreService,
  ) {}

  /**
   * --------------------------------------------------------------------------
   * User Registration Pipeline
   * --------------------------------------------------------------------------
   */

  async register(
    dto: RegisterDto,
  ) {
    const existingUser =
      await this.usersService.findByEmail(
        dto.email,
      );

    if (existingUser) {
      throw new ForbiddenException(
        'Account already exists',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Password Hashing
     * ------------------------------------------------------------------------
     */

    const passwordHash =
      await this.passwordService.hash(
        dto.password,
      );

    /**
     * ------------------------------------------------------------------------
     * User Creation
     * ------------------------------------------------------------------------
     */

    const user =
      await this.usersService.create({
        email: dto.email,
        password: passwordHash,
        roles: ['user'],
      });

    this.logger.log({
      event:
        'user_registered',

      userId: user.id,

      email: user.email,
    });

    return {
      success: true,

      message:
        'Registration successful',

      user: {
        id: user.id,
        email: user.email,
      },
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Adaptive Login Pipeline
   * --------------------------------------------------------------------------
   */

  async login(
    dto: LoginDto,
    metadata: {
      ip?: string;
      userAgent?: string;
      fingerprint?: string;
    },
  ) {
    /**
     * ------------------------------------------------------------------------
     * User Resolution
     * ------------------------------------------------------------------------
     */

    const user =
      await this.usersService.findByEmail(
        dto.email,
      );

    if (!user) {
      throw new UnauthorizedException(
        'Invalid credentials',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Credential Verification
     * ------------------------------------------------------------------------
     */

    const passwordValid =
      await bcrypt.compare(
        dto.password,
        user.password,
      );

    if (!passwordValid) {
      throw new UnauthorizedException(
        'Invalid credentials',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Adaptive Risk Evaluation
     * ------------------------------------------------------------------------
     */

    const risk =
      this.riskScoreService.calculateLoginRisk(
        {
          ip:
            metadata.ip,

          fingerprint:
            metadata.fingerprint,

          userAgent:
            metadata.userAgent,
        },
      );

    /**
     * ------------------------------------------------------------------------
     * High-Risk Access Mitigation
     * ------------------------------------------------------------------------
     */

    if (
      risk.score >= 90
    ) {
      const event =
        new SuspiciousLoginEvent(
          user.id,
          metadata.ip || '',
          risk.score,
        );

      this.logger.warn(event);

      throw new ForbiddenException({
        success: false,

        message:
          'Suspicious login detected',

        riskScore:
          risk.score,
      });
    }

    /**
     * ------------------------------------------------------------------------
     * Distributed Session Creation
     * ------------------------------------------------------------------------
     */

    const session =
      await this.sessionService.create({
        userId: user.id,
        email: user.email,
        roles: user.roles,
        fingerprint:
          metadata.fingerprint,
        ipAddress:
          metadata.ip,
        userAgent:
          metadata.userAgent,
      });

    /**
     * ------------------------------------------------------------------------
     * Token Generation
     * ------------------------------------------------------------------------
     */

    const tokens =
      await this.tokenService.generateTokens(
        {
          sub: user.id,
          email: user.email,
          roles: user.roles,
          sessionId:
            session.sessionId,
          fingerprint:
            metadata.fingerprint,
          riskScore:
            risk.score,
        },
      );

    /**
     * ------------------------------------------------------------------------
     * Refresh Token Persistence
     * ------------------------------------------------------------------------
     */

    await this.sessionService.attachRefreshToken(
      session.sessionId,
      tokens.refreshToken,
    );

    /**
     * ------------------------------------------------------------------------
     * Security Telemetry
     * ------------------------------------------------------------------------
     */

    const loginEvent =
      new LoginAttemptEvent(
        user.id,
        metadata.ip || '',
        true,
      );

    this.logger.log(loginEvent);

    return {
      success: true,

      message:
        'Authentication successful',

      accessToken:
        tokens.accessToken,

      refreshToken:
        tokens.refreshToken,

      session,
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Refresh Token Rotation
   * --------------------------------------------------------------------------
   */

  async refresh(
    dto: RefreshTokenDto,
  ) {
    /**
     * ------------------------------------------------------------------------
     * Token Verification
     * ------------------------------------------------------------------------
     */

    const payload =
      await this.tokenService.verifyRefreshToken(
        dto.refreshToken,
      );

    /**
     * ------------------------------------------------------------------------
     * Session Validation
     * ------------------------------------------------------------------------
     */

    const session =
      await this.sessionService.findById(
        payload.sessionId,
      );

    if (!session) {
      throw new UnauthorizedException(
        'Session expired',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Refresh Rotation Validation
     * ------------------------------------------------------------------------
     */

    const valid =
      await this.sessionService.validateRefreshToken(
        session.sessionId,
        dto.refreshToken,
      );

    if (!valid) {
      throw new UnauthorizedException(
        'Invalid refresh token',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * New Token Pair Generation
     * ------------------------------------------------------------------------
     */

    const tokens =
      await this.tokenService.generateTokens(
        {
          sub: payload.sub,
          email: payload.email,
          roles: payload.roles,
          sessionId:
            payload.sessionId,
          fingerprint:
            payload.fingerprint,
        },
      );

    /**
     * ------------------------------------------------------------------------
     * Refresh Rotation Persistence
     * ------------------------------------------------------------------------
     */

    await this.sessionService.attachRefreshToken(
      session.sessionId,
      tokens.refreshToken,
    );

    return {
      success: true,

      accessToken:
        tokens.accessToken,

      refreshToken:
        tokens.refreshToken,
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Distributed Logout Pipeline
   * --------------------------------------------------------------------------
   */

  async logout(
    sessionId: string,
  ) {
    await this.sessionService.revoke(
      sessionId,
    );

    this.logger.log({
      event:
        'session_revoked',

      sessionId,
    });

    return {
      success: true,

      message:
        'Logout successful',
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Session Validation
   * --------------------------------------------------------------------------
   */

  async validateSession(
    sessionId: string,
  ): Promise<SessionInterface | null> {
    return this.sessionService.findById(
      sessionId,
    );
  }
}