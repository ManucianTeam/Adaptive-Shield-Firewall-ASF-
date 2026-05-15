/* ============================================================
 * ASF — Adaptive Shield Firewall
 * API Key Authorization Guard
 * File: api-key.guard.ts
 * ============================================================
 *
 * PURPOSE:
 * Enforces API key authentication and request
 * authorization for machine-to-machine traffic,
 * internal services, and privileged API consumers.
 *
 * SECURITY OBJECTIVES:
 * - Prevent unauthorized API access
 * - Protect internal service boundaries
 * - Detect API abuse patterns
 * - Enforce key-based identity validation
 * - Generate machine-traffic telemetry
 *
 * DESIGN PRINCIPLES:
 * - Zero-trust request validation
 * - Constant-time secret comparison
 * - Minimal information disclosure
 * - Lightweight authorization flow
 * - Structured observability
 *
 * IMPORTANT:
 * NEVER:
 * - expose raw API keys
 * - log sensitive credentials
 * - trust unhashed client identifiers
 * - leak validation internals
 *
 * RECOMMENDED:
 * - rotate API keys periodically
 * - store hashed keys only
 * - bind keys to scopes/permissions
 * - implement expiration policies
 * - integrate adaptive risk scoring
 *
 * ============================================================
 */

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';

import { Request } from 'express';

import { timingSafeEqual } from 'crypto';

/**
 * ============================================================
 * API Key Authorization Guard
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - API key validation
 * - Machine identity enforcement
 * - Service-to-service authorization
 * - Traffic telemetry generation
 * ============================================================
 */

@Injectable()
export class ApiKeyGuard implements CanActivate {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(ApiKeyGuard.name);

  constructor(private readonly configService: ConfigService) {}

  /**
   * ============================================================
   * Guard Execution Entry Point
   * ============================================================
   */

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    /**
     * ==========================================================
     * Extract API Key
     * ==========================================================
     *
     * SUPPORTED HEADERS:
     * - x-api-key
     * - authorization: ApiKey <key>
     * ==========================================================
     */

    const headerKey = request.headers['x-api-key'];

    const authorizationHeader = request.headers['authorization'];

    let providedApiKey: string | undefined;

    if (typeof headerKey === 'string') {
      providedApiKey = headerKey;
    }

    if (
      !providedApiKey &&
      typeof authorizationHeader === 'string' &&
      authorizationHeader.startsWith('ApiKey ')
    ) {
      providedApiKey = authorizationHeader.replace('ApiKey ', '');
    }

    /**
     * ==========================================================
     * Missing Credential Validation
     * ==========================================================
     */

    if (!providedApiKey) {
      this.logger.warn({
        event: 'API_KEY_MISSING',

        path: request.originalUrl,

        method: request.method,

        ip: request.ip || request.socket?.remoteAddress,

        timestamp: Date.now(),
      });

      throw new UnauthorizedException('API key required.');
    }

    /**
     * ==========================================================
     * Expected API Key Resolution
     * ==========================================================
     */

    const expectedApiKey = this.configService.get<string>(
      'ASF_INTERNAL_API_KEY',
    );

    if (!expectedApiKey) {
      this.logger.error({
        event: 'API_KEY_CONFIGURATION_ERROR',

        reason: 'Missing ASF_INTERNAL_API_KEY configuration.',

        timestamp: Date.now(),
      });

      throw new ForbiddenException('API authentication unavailable.');
    }

    /**
     * ==========================================================
     * Constant-Time Credential Comparison
     * ==========================================================
     *
     * SECURITY:
     * Prevents timing-attack leakage.
     * ==========================================================
     */

    const providedBuffer = Buffer.from(providedApiKey);

    const expectedBuffer = Buffer.from(expectedApiKey);

    const validLength = providedBuffer.length === expectedBuffer.length;

    const isValid =
      validLength && timingSafeEqual(providedBuffer, expectedBuffer);

    /**
     * ==========================================================
     * Invalid Credential Handling
     * ==========================================================
     */

    if (!isValid) {
      this.logger.warn({
        event: 'INVALID_API_KEY',

        path: request.originalUrl,

        method: request.method,

        ip: request.ip || request.socket?.remoteAddress,

        userAgent: request.headers['user-agent'],

        timestamp: Date.now(),
      });

      throw new ForbiddenException('Invalid API credentials.');
    }

    /**
     * ==========================================================
     * Machine Identity Context Injection
     * ==========================================================
     *
     * Inject lightweight machine identity
     * metadata for downstream services.
     * ==========================================================
     */

    (request as any).apiIdentity = {
      type: 'service',

      authenticated: true,

      authenticationMethod: 'api-key',

      timestamp: Date.now(),
    };

    /**
     * ==========================================================
     * Successful Authorization Telemetry
     * ==========================================================
     */

    this.logger.log({
      event: 'API_KEY_AUTHORIZED',

      path: request.originalUrl,

      method: request.method,

      timestamp: Date.now(),
    });

    return true;
  }
}
