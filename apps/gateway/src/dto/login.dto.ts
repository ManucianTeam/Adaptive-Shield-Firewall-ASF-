/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Authentication DTO Layer
 * File: login.dto.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines the inbound authentication payload contract
 * for the ASF identity gateway layer.
 *
 * SECURITY OBJECTIVES:
 * - Strong request validation
 * - Input normalization
 * - Injection surface reduction
 * - Authentication schema enforcement
 * - Gateway integrity protection
 *
 * DESIGN PRINCIPLES:
 * - Strict validation boundaries
 * - Minimal trust assumptions
 * - Explicit payload constraints
 * - Low-overhead validation flow
 *
 * USED BY:
 * - Authentication Controller
 * - Identity Gateway
 * - Behavioral Risk Engine
 * - Session Validation Layer
 *
 * ============================================================
 */

import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
  Matches,
  MaxLength,
} from 'class-validator';

import { Transform } from 'class-transformer';

/**
 * ============================================================
 * Login DTO
 * ============================================================
 *
 * SECURITY NOTES:
 * - Email normalization reduces identity duplication
 * - Password constraints reduce malformed payloads
 * - Device metadata supports behavioral analysis
 * - Request fingerprint fields remain optional
 *   to preserve compatibility with lightweight clients
 * ============================================================
 */

export class LoginDto {
  /**
   * ============================================================
   * User Identity Field
   * ============================================================
   *
   * Accepts:
   * - Email-based identity
   *
   * SECURITY:
   * - Normalized to lowercase
   * - Trimmed before validation
   * - Strict RFC-compatible email validation
   * ============================================================
   */

  @IsEmail()
  @IsNotEmpty()
  @MaxLength(320)
  @Transform(({ value }) =>
    typeof value === 'string' ? value.trim().toLowerCase() : value,
  )
  email: string;

  /**
   * ============================================================
   * Password Field
   * ============================================================
   *
   * SECURITY REQUIREMENTS:
   * - Minimum entropy enforcement
   * - Prevent malformed credential payloads
   * - Reduce weak authentication attempts
   *
   * VALIDATION:
   * - Minimum length: 8
   * - Maximum length: 128
   * - At least:
   *   - one uppercase character
   *   - one lowercase character
   *   - one numeric character
   * ============================================================
   */

  @IsString()
  @IsNotEmpty()
  @Length(8, 128)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/, {
    message:
      'Password must contain uppercase, lowercase, and numeric characters.',
  })
  password: string;

  /**
   * ============================================================
   * Device Identifier
   * ============================================================
   *
   * PURPOSE:
   * Supports behavioral continuity tracking
   * and adaptive risk correlation.
   *
   * EXAMPLES:
   * - browser fingerprint hash
   * - mobile device identifier
   * - trusted session identifier
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @MaxLength(256)
  deviceId?: string;

  /**
   * ============================================================
   * Client Fingerprint
   * ============================================================
   *
   * PURPOSE:
   * Optional lightweight fingerprint signal
   * forwarded by frontend clients.
   *
   * SECURITY NOTE:
   * Never fully trust client-provided fingerprints.
   * Always correlate with server-side telemetry.
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @MaxLength(512)
  fingerprint?: string;

  /**
   * ============================================================
   * Session Correlation Identifier
   * ============================================================
   *
   * PURPOSE:
   * Enables distributed tracing and
   * authentication request correlation.
   *
   * USED FOR:
   * - audit logging
   * - telemetry aggregation
   * - anomaly investigation
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @MaxLength(128)
  correlationId?: string;
}
