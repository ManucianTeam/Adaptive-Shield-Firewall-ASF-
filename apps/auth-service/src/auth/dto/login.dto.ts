// apps/auth-service/src/auth/dto/login.dto.ts

import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

/**
 * ============================================================================
 * ASF Login DTO
 * ============================================================================
 *
 * Authentication payload validation contract used by
 * the ASF authentication pipeline.
 *
 * Responsibilities:
 *
 *  - credential structure validation
 *  - malformed payload rejection
 *  - attack surface minimization
 *  - telemetry enrichment readiness
 *  - adaptive authentication support
 *
 * Security Characteristics:
 *
 *  - strict input validation
 *  - credential boundary enforcement
 *  - fingerprint-aware authentication
 *  - distributed session compatibility
 *  - AI-assisted risk analysis readiness
 *
 * Integrated With:
 *
 *  - AuthController
 *  - AuthService
 *  - JWT authentication pipeline
 *  - AI security analyzers
 *  - session orchestration layer
 *
 * ============================================================================
 */

export class LoginDto {
  /**
   * --------------------------------------------------------------------------
   * User Identity
   * --------------------------------------------------------------------------
   *
   * Primary authentication identifier.
   */

  @IsString()
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(255)
  email: string;

  /**
   * --------------------------------------------------------------------------
   * Account Secret
   * --------------------------------------------------------------------------
   *
   * User credential validated against
   * the password hashing subsystem.
   */

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(128)
  password: string;

  /**
   * --------------------------------------------------------------------------
   * Device Fingerprint
   * --------------------------------------------------------------------------
   *
   * Optional client fingerprint used for:
   *
   *  - adaptive trust scoring
   *  - suspicious login detection
   *  - distributed session correlation
   *  - anomaly analysis
   */

  @IsOptional()
  @IsString()
  @MaxLength(512)
  fingerprint?: string;

  /**
   * --------------------------------------------------------------------------
   * Client Device Metadata
   * --------------------------------------------------------------------------
   *
   * Optional high-level device descriptor.
   */

  @IsOptional()
  @IsString()
  @MaxLength(255)
  deviceName?: string;
}