/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Payload Sanitization Interceptor
 * File: sanitize.interceptor.ts
 * ============================================================
 *
 * PURPOSE:
 * Performs lightweight request payload
 * sanitization and malicious-input reduction
 * before execution reaches protected services.
 *
 * SECURITY OBJECTIVES:
 * - Reduce injection attack surface
 * - Neutralize dangerous payload patterns
 * - Enforce safe request normalization
 * - Mitigate malformed request vectors
 * - Protect downstream service integrity
 *
 * DESIGN PRINCIPLES:
 * - Low-latency sanitization
 * - Deterministic normalization
 * - Minimal payload mutation
 * - Non-destructive filtering
 * - Lightweight execution path
 *
 * IMPORTANT:
 * This interceptor is NOT a replacement for:
 * - parameterized queries
 * - ORM protections
 * - output encoding
 * - database validation
 * - CSP enforcement
 *
 * NEVER:
 * - trust sanitized input blindly
 * - mutate cryptographic payloads
 * - sanitize binary streams inline
 * - perform heavy parsing operations
 *
 * ============================================================
 */

import {
  CallHandler,
  ExecutionContext,
  Injectable,
  Logger,
  NestInterceptor,
} from '@nestjs/common';

import { Observable } from 'rxjs';

import { Request } from 'express';
import sanitizeHtml from 'sanitize-html';

/**
 * ============================================================
 * Payload Sanitization Interceptor
 * ============================================================
 *
 * RESPONSIBILITIES:
 * - Request normalization
 * - Injection surface reduction
 * - Dangerous payload filtering
 * - Security telemetry generation
 * ============================================================
 */

@Injectable()
export class SanitizeInterceptor implements NestInterceptor {
  /**
   * ============================================================
   * Structured Security Logger
   * ============================================================
   */

  private readonly logger = new Logger(SanitizeInterceptor.name);

  /**
   * ============================================================
   * Interceptor Entry Point
   * ============================================================
   */

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const httpContext = context.switchToHttp();

    const request = httpContext.getRequest<Request>();

    /**
     * ==========================================================
     * Request Metadata
     * ==========================================================
     */

    const ip = request.ip || request.socket?.remoteAddress || 'unknown';

    const path = request.originalUrl;

    /**
     * ==========================================================
     * Payload Sanitization Pipeline
     * ==========================================================
     */

    if (request.body && typeof request.body === 'object') {
      request.body = this.sanitizeObject(request.body);
    }

    /**
     * ==========================================================
     * Query Sanitization
     * ==========================================================
     */

    if (request.query && typeof request.query === 'object') {
      request.query = this.sanitizeObject(request.query);
    }

    /**
     * ==========================================================
     * Security Telemetry
     * ==========================================================
     */

    this.logger.log({
      event: 'PAYLOAD_SANITIZED',

      path,

      ip,

      timestamp: Date.now(),
    });

    return next.handle();
  }

  /**
   * ============================================================
   * Recursive Object Sanitizer
   * ============================================================
   *
   * PURPOSE:
   * Traverses request structures and applies
   * lightweight sanitization recursively.
   * ============================================================
   */

  private sanitizeObject(value: any): any {
    /**
     * ==========================================================
     * Array Traversal
     * ==========================================================
     */

    if (Array.isArray(value)) {
      return value.map((item) => this.sanitizeObject(item));
    }

    /**
     * ==========================================================
     * Nested Object Traversal
     * ==========================================================
     */

    if (value && typeof value === 'object') {
      const sanitizedObject: Record<string, unknown> = {};

      for (const key of Object.keys(value)) {
        sanitizedObject[key] = this.sanitizeObject(value[key]);
      }

      return sanitizedObject;
    }

    /**
     * ==========================================================
     * Primitive String Sanitization
     * ==========================================================
     */

    if (typeof value === 'string') {
      return this.sanitizeString(value);
    }

    return value;
  }

  /**
   * ============================================================
   * Lightweight String Sanitizer
   * ============================================================
   *
   * TARGETS:
   * - basic XSS payloads
   * - script injections
   * - HTML tag injection
   * - dangerous inline events
   *
   * NOTE:
   * Enterprise deployments should combine:
   * - CSP policies
   * - contextual output encoding
   * - advanced HTML sanitizers
   * ============================================================
   */

  private sanitizeString(value: string): string {
    let sanitized = value;
    let previous: string;

    do {
      previous = sanitized;

      sanitized = sanitized
        /**
         * ========================================================
         * Script Tag Neutralization
         * ========================================================
         */

        .replace(/<script.*?>.*?<\/script>/gi, '')

        /**
         * ========================================================
         * Dangerous Inline Event Removal
         * ========================================================
         */

        .replace(/on\w+=".*?"/gi, '')

        /**
         * ========================================================
         * HTML Tag Stripping
         * ========================================================
         */

        .replace(/<[^>]+>/g, '')
    const htmlSanitized = sanitizeHtml(value, {
      allowedTags: [],
      allowedAttributes: {},
    });

    return (
      htmlSanitized
        /**
         * ========================================================
         * SQL Injection Pattern Reduction
         * ========================================================
         */

        .replace(/('|--|;|\/\*|\*\/)/g, '')

        /**
         * ========================================================
         * Whitespace Normalization
         * ========================================================
         */

        .trim();
    } while (sanitized !== previous);

    return sanitized;
  }
}
