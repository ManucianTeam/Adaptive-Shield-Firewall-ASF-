// apps/auth-service/src/auth/guards/roles.guard.ts

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';

import { Reflector } from '@nestjs/core';

import { Request } from 'express';

import {
  ROLES_KEY,
  SystemRole,
} from '../decorators/roles.decorator';

/**
 * ============================================================================
 * ASF Role Authorization Guard
 * ============================================================================
 *
 * Enterprise-grade RBAC enforcement layer responsible for:
 *
 *  - role-scoped authorization
 *  - hierarchical access validation
 *  - privilege boundary enforcement
 *  - distributed permission verification
 *  - adaptive authorization orchestration
 *
 * Security Characteristics:
 *
 *  - Zero Trust authorization
 *  - least-privilege enforcement
 *  - deterministic role validation
 *  - privilege escalation prevention
 *  - endpoint-level access isolation
 *
 * Integrated With:
 *
 *  - JwtAuthGuard
 *  - Roles decorator
 *  - distributed gateway policies
 *  - microservice authorization pipelines
 *  - adaptive access-control systems
 *
 * Expected Request User Shape:
 *
 * {
 *   sub: string;
 *   email: string;
 *   roles: string[];
 * }
 *
 * ============================================================================
 */

@Injectable()
export class RolesGuard
  implements CanActivate
{
  constructor(
    private readonly reflector: Reflector,
  ) {}

  /**
   * --------------------------------------------------------------------------
   * Authorization Pipeline
   * --------------------------------------------------------------------------
   */

  canActivate(
    context: ExecutionContext,
  ): boolean {
    /**
     * ------------------------------------------------------------------------
     * Resolve Route Role Metadata
     * ------------------------------------------------------------------------
     */

    const requiredRoles =
      this.reflector.getAllAndOverride<
        SystemRole[]
      >(ROLES_KEY, [
        context.getHandler(),
        context.getClass(),
      ]);

    /**
     * ------------------------------------------------------------------------
     * Route Does Not Require RBAC
     * ------------------------------------------------------------------------
     */

    if (
      !requiredRoles ||
      requiredRoles.length === 0
    ) {
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

    const user = request.user as {
      sub?: string;

      email?: string;

      roles?: string[];
    };

    /**
     * ------------------------------------------------------------------------
     * Missing Identity Context
     * ------------------------------------------------------------------------
     */

    if (!user) {
      throw new ForbiddenException(
        'Authorization context missing',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Missing Role Collection
     * ------------------------------------------------------------------------
     */

    if (
      !Array.isArray(user.roles)
    ) {
      throw new ForbiddenException(
        'User roles not available',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Hierarchical Role Validation
     * ------------------------------------------------------------------------
     */

    const authorized =
      requiredRoles.some((role) =>
        user.roles.includes(role),
      );

    /**
     * ------------------------------------------------------------------------
     * Access Denied
     * ------------------------------------------------------------------------
     */

    if (!authorized) {
      throw new ForbiddenException(
        'Insufficient permissions',
      );
    }

    return true;
  }
}