/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Role-Based Authorization Guard
 * File: role.guard.ts
 * ============================================================
 *
 * PURPOSE:
 * Enforces fine-grained role-based access control
 * across ASF protected resources and privileged
 * security orchestration endpoints.
 *
 * SECURITY OBJECTIVES:
 * - Enforce authorization boundaries
 * - Prevent privilege escalation
 * - Protect sensitive control-plane operations
 * - Generate authorization telemetry
 * - Support forensic access tracing
 *
 * DESIGN PRINCIPLES:
 * - Zero-trust authorization
 * - Explicit privilege validation
 * - Deterministic policy enforcement
 * - Minimal information disclosure
 * - Lightweight request-path execution
 *
 * IMPORTANT:
 * NEVER:
 * - trust client-provided roles
 * - expose RBAC topology
 * - leak policy evaluation logic
 * - reveal authorization hierarchy
 *
 * RECOMMENDED:
 * - least-privilege enforcement
 * - centralized policy management
 * - audit logging integration
 * - adaptive authorization correlation
 *
 * ============================================================
 */

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';

import { Reflector } from '@nestjs/core';

import { Request } from 'express';

/**
 * ============================================================
 * Supported Role Types
 * ============================================================
 */

export enum Role {
  USER = 'user',

  ADMIN = 'admin',

  SUPER_ADMIN = 'super_admin',

  SECURITY_ADMIN = 'security_admin',

  SECURITY_ANALYST = 'security_analyst',

  AUDITOR = 'auditor',
}

/**
 * ============================================================
 * Role Authorization Guard
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Role validation
 * - Privilege enforcement
 * - Authorization telemetry
 * - Access observability
 * ============================================================
 */

@Injectable()
export class RoleGuard implements CanActivate {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(RoleGuard.name);

  constructor(private readonly reflector: Reflector) {}

  /**
   * ============================================================
   * Guard Execution Entry Point
   * ============================================================
   */

  canActivate(context: ExecutionContext): boolean {
    /**
     * ==========================================================
     * Required Role Resolution
     * ==========================================================
     */

    const requiredRoles = this.reflector.getAllAndOverride<Role[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);

    /**
     * ==========================================================
     * Public Route Handling
     * ==========================================================
     */

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();

    /**
     * ==========================================================
     * Authenticated Identity Resolution
     * ==========================================================
     */

    const user = (request as any).user;

    /**
     * ==========================================================
     * Missing Identity Validation
     * ==========================================================
     */

    if (!user) {
      this.logger.warn({
        event: 'ROLE_VALIDATION_FAILED',

        reason: 'Missing authenticated identity.',

        path: request.originalUrl,

        method: request.method,

        timestamp: Date.now(),
      });

      throw new ForbiddenException('Access denied.');
    }

    /**
     * ==========================================================
     * Role Authorization Evaluation
     * ==========================================================
     */

    const hasRequiredRole = requiredRoles.includes(user.role);

    /**
     * ==========================================================
     * Authorization Failure Handling
     * ==========================================================
     */

    if (!hasRequiredRole) {
      this.logger.warn({
        event: 'ROLE_ACCESS_DENIED',

        userId: user.id,

        role: user.role,

        requiredRoles,

        path: request.originalUrl,

        method: request.method,

        ip: request.ip || request.socket?.remoteAddress,

        userAgent: request.headers['user-agent'],

        timestamp: Date.now(),
      });

      throw new ForbiddenException('Insufficient permissions.');
    }

    /**
     * ==========================================================
     * Successful Authorization Telemetry
     * ==========================================================
     */

    this.logger.log({
      event: 'ROLE_ACCESS_GRANTED',

      userId: user.id,

      role: user.role,

      requiredRoles,

      path: request.originalUrl,

      method: request.method,

      timestamp: Date.now(),
    });

    return true;
  }
}
