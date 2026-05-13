// apps/auth-service/src/auth/guards/jwt-auth.guard.ts

import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

import { Reflector } from '@nestjs/core';

import { JwtService } from '@nestjs/jwt';

import { Request } from 'express';

import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

/**
 * ============================================================================
 * ASF JWT Authentication Guard
 * ============================================================================
 *
 * Enterprise-grade stateless authentication guard responsible for:
 *
 *  - JWT access-token validation
 *  - protected route enforcement
 *  - identity extraction
 *  - request authentication context injection
 *  - adaptive access verification
 *  - distributed authentication compatibility
 *
 * Security Characteristics:
 *
 *  - Bearer-token enforcement
 *  - cryptographic signature validation
 *  - expiration verification
 *  - tamper detection
 *  - stateless identity propagation
 *  - Zero Trust request validation
 *
 * Integrated With:
 *
 *  - Public decorator
 *  - RolesGuard
 *  - distributed API gateways
 *  - adaptive security middleware
 *  - session orchestration systems
 *
 * ============================================================================
 */

@Injectable()
export class JwtAuthGuard
  implements CanActivate
{
  constructor(
    private readonly reflector: Reflector,

    private readonly jwtService: JwtService,
  ) {}

  /**
   * --------------------------------------------------------------------------
   * Authentication Pipeline
   * --------------------------------------------------------------------------
   */

  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
    /**
     * ------------------------------------------------------------------------
     * Public Route Bypass
     * ------------------------------------------------------------------------
     */

    const isPublic =
      this.reflector.getAllAndOverride<boolean>(
        IS_PUBLIC_KEY,
        [
          context.getHandler(),
          context.getClass(),
        ],
      );

    if (isPublic) {
      return true;
    }

    /**
     * ------------------------------------------------------------------------
     * Request Context
     * ------------------------------------------------------------------------
     */

    const request =
      context
        .switchToHttp()
        .getRequest<Request>();

    /**
     * ------------------------------------------------------------------------
     * Extract Authorization Token
     * ------------------------------------------------------------------------
     */

    const token =
      this.extractBearerToken(request);

    if (!token) {
      throw new UnauthorizedException(
        'Missing authentication token',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Token Verification
     * ------------------------------------------------------------------------
     */

    try {
      const payload =
        await this.jwtService.verifyAsync(
          token,
          {
            secret:
              process.env.JWT_ACCESS_SECRET,
          },
        );

      /**
       * ----------------------------------------------------------------------
       * Inject Identity Context
       * ----------------------------------------------------------------------
       */

      request.user = payload;

      return true;
    } catch (error) {
      throw new UnauthorizedException(
        'Invalid or expired authentication token',
      );
    }
  }

  /**
   * --------------------------------------------------------------------------
   * Bearer Token Extraction
   * --------------------------------------------------------------------------
   */

  private extractBearerToken(
    request: Request,
  ): string | null {
    const authorization =
      request.headers.authorization;

    if (!authorization) {
      return null;
    }

    const [type, token] =
      authorization.split(' ');

    if (
      type !== 'Bearer' ||
      !token
    ) {
      return null;
    }

    return token;
  }
}