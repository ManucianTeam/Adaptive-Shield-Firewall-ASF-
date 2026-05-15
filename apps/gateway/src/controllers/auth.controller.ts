import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Ip,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';

import { Request } from 'express';

import { AuthService } from './auth.service';
import { AuthGuard } from './guards/auth.guard';

/**
 * ============================================================
 * ASF — Adaptive Shield Firewall
 * Authentication Gateway Controller
 * ============================================================
 *
 * SECURITY ROLE:
 * This controller acts as the identity ingress layer of ASF.
 * Every authentication event contributes to:
 *
 * - Behavioral fingerprint enrichment
 * - Adaptive risk scoring
 * - Session integrity validation
 * - Threat intelligence correlation
 * - Credential abuse detection
 * - Replay attack mitigation
 *
 * DESIGN PRINCIPLES:
 * - Stateless authentication
 * - Behavior-aware request processing
 * - Zero-Trust aligned identity validation
 * - Low-latency authentication orchestration
 * - Security telemetry generation
 *
 * NOTE:
 * This controller should remain lightweight.
 * Heavy fingerprint computation and anomaly analysis
 * must be delegated to worker threads or external services.
 * ============================================================
 */

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ============================================================
  // LOGIN
  // ============================================================

  /**
   * Primary authentication entrypoint.
   *
   * SECURITY FLOW:
   * 1. Request metadata extraction
   * 2. Behavioral context construction
   * 3. Credential validation
   * 4. Risk evaluation
   * 5. Session/token generation
   * 6. Telemetry emission
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body()
    body: {
      email: string;
      password: string;
    },

    @Req() req: Request,

    @Ip() ip: string,
  ) {
    const context = this.buildSecurityContext(req, ip);

    return this.authService.login({
      email: body.email,
      password: body.password,
      context,
    });
  }

  // ============================================================
  // REGISTER
  // ============================================================

  /**
   * Identity registration endpoint.
   *
   * Creates initial behavioral baseline
   * for future authentication correlation.
   */
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(
    @Body()
    body: {
      email: string;
      password: string;
    },

    @Req() req: Request,

    @Ip() ip: string,
  ) {
    const context = this.buildSecurityContext(req, ip);

    return this.authService.register({
      email: body.email,
      password: body.password,
      context,
    });
  }

  // ============================================================
  // TOKEN VALIDATION
  // ============================================================

  /**
   * Validates session integrity and token authenticity.
   *
   * Used by:
   * - Gateway authorization layer
   * - Internal service verification
   * - Behavioral continuity tracking
   */
  @Post('validate')
  @HttpCode(HttpStatus.OK)
  async validate(
    @Body()
    body: {
      accessToken: string;
    },

    @Req() req: Request,

    @Ip() ip: string,
  ) {
    const context = this.buildSecurityContext(req, ip);

    return this.authService.validateAccessToken({
      accessToken: body.accessToken,
      context,
    });
  }

  // ============================================================
  // TOKEN REFRESH
  // ============================================================

  /**
   * Refresh token rotation endpoint.
   *
   * SECURITY OBJECTIVES:
   * - Session continuity enforcement
   * - Replay attack mitigation
   * - Token rotation hardening
   * - Device continuity verification
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Body()
    body: {
      refreshToken: string;
    },

    @Req() req: Request,

    @Ip() ip: string,
  ) {
    const context = this.buildSecurityContext(req, ip);

    return this.authService.refreshToken({
      refreshToken: body.refreshToken,
      context,
    });
  }

  // ============================================================
  // LOGOUT
  // ============================================================

  /**
   * Session termination endpoint.
   *
   * Invalidates:
   * - Access token
   * - Refresh token
   * - Session cache state
   * - Behavioral continuity chain
   */
  @Post('logout')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @Body()
    body: {
      accessToken: string;
    },
  ) {
    return this.authService.logout({
      accessToken: body.accessToken,
    });
  }

  // ============================================================
  // SESSION REVOKE
  // ============================================================

  /**
   * Force revoke active session.
   *
   * Used during:
   * - Incident response
   * - Threat containment
   * - Credential compromise mitigation
   */
  @Post('revoke')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  async revokeSession(
    @Body()
    body: {
      sessionId: string;
    },
  ) {
    return this.authService.revokeSession({
      sessionId: body.sessionId,
    });
  }

  // ============================================================
  // INTERNAL SECURITY CONTEXT BUILDER
  // ============================================================

  /**
   * Constructs lightweight behavioral metadata
   * for downstream security engines.
   *
   * IMPORTANT:
   * Keep this operation minimal to avoid
   * request-path latency inflation.
   */
  private buildSecurityContext(req: Request, ip: string) {
    const userAgent = req.headers['user-agent'] || 'unknown';

    const forwardedFor = (req.headers['x-forwarded-for'] as string) || null;

    const requestId = (req.headers['x-request-id'] as string) || null;

    return {
      ip,
      forwardedFor,
      userAgent,
      requestId,

      method: req.method,
      path: req.originalUrl,

      timestamp: Date.now(),

      headers: {
        accept: req.headers['accept'],
        contentType: req.headers['content-type'],
        origin: req.headers['origin'],
        referer: req.headers['referer'],
      },
    };
  }
}
