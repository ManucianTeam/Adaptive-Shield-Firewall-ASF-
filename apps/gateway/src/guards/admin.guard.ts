/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Administrative Authorization Guard
 * File: admin.guard.ts
 * ============================================================
 *
 * PURPOSE:
 * Enforces privileged-access authorization for
 * administrative and security-sensitive endpoints.
 *
 * SECURITY OBJECTIVES:
 * - Prevent unauthorized control-plane access
 * - Enforce role-based authorization boundaries
 * - Protect security orchestration endpoints
 * - Detect privilege escalation attempts
 * - Generate authorization telemetry
 *
 * DESIGN PRINCIPLES:
 * - Zero-trust authorization model
 * - Explicit privilege validation
 * - Deterministic access enforcement
 * - Minimal policy disclosure
 * - Lightweight execution path
 *
 * IMPORTANT:
 * This guard protects:
 * - Administrative APIs
 * - Security orchestration interfaces
 * - Risk engine controls
 * - Policy management endpoints
 * - Incident response operations
 *
 * NEVER trust:
 * - client-side role claims
 * - unsigned metadata
 * - unverified JWT payloads
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

import { Request } from 'express';

/**
 * ============================================================
 * Administrative Authorization Guard
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Privileged access validation
 * - Role verification
 * - Security telemetry generation
 * - Authorization observability
 * ============================================================
 */

@Injectable()
export class AdminGuard implements CanActivate {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(AdminGuard.name);

  /**
   * ============================================================
   * Access Validation Entry Point
   * ============================================================
   */

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    /**
     * ==========================================================
     * Extract Authenticated Identity
     * ==========================================================
     *
     * EXPECTATION:
     * Previous authentication middleware
     * or JWT guard should attach verified
     * identity context to the request object.
     * ==========================================================
     */

    const user = (request as any).user;

    /**
     * ==========================================================
     * Authentication Presence Validation
     * ==========================================================
     */

    if (!user) {
      this.logger.warn({
        event: 'ADMIN_ACCESS_DENIED',

        reason: 'Unauthenticated administrative access attempt.',

        path: request.originalUrl,

        ip: request.ip || request.socket?.remoteAddress,

        timestamp: Date.now(),
      });

      throw new UnauthorizedException('Authentication required.');
    }

    /**
     * ==========================================================
     * Administrative Role Validation
     * ==========================================================
     */

    const allowedRoles = ['admin', 'super_admin', 'security_admin'];

    const hasAccess = allowedRoles.includes(user.role);

    /**
     * ==========================================================
     * Privilege Escalation Detection
     * ==========================================================
     */

    if (!hasAccess) {
      this.logger.warn({
        event: 'PRIVILEGED_ACCESS_DENIED',

        reason: 'Insufficient administrative privileges.',

        userId: user.id,

        role: user.role,

        path: request.originalUrl,

        method: request.method,

        ip: request.ip || request.socket?.remoteAddress,

        userAgent: request.headers['user-agent'],

        timestamp: Date.now(),
      });

      throw new ForbiddenException('Administrative privileges required.');
    }

    /**
     * ==========================================================
     * Successful Administrative Authorization
     * ==========================================================
     */

    this.logger.log({
      event: 'ADMIN_ACCESS_GRANTED',

      userId: user.id,

      role: user.role,

      path: request.originalUrl,

      method: request.method,

      timestamp: Date.now(),
    });

    return true;
  }
}
