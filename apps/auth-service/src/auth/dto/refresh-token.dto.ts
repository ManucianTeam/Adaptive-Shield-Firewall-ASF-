// apps/auth-service/src/auth/dto/refresh-token.dto.ts

import {
  IsJWT,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';

/**
 * ============================================================================
 * ASF Refresh Token DTO
 * ============================================================================
 *
 * Validation contract for token rotation
 * and session continuation workflows.
 *
 * Responsibilities:
 *
 *  - refresh token validation
 *  - malformed token rejection
 *  - session continuation integrity
 *  - token rotation enforcement
 *  - distributed authentication compatibility
 *
 * Security Characteristics:
 *
 *  - strict JWT structure validation
 *  - replay mitigation readiness
 *  - adaptive session verification
 *  - fingerprint-aware token refresh
 *  - distributed revocation support
 *
 * Integrated With:
 *
 *  - AuthController
 *  - AuthService
 *  - TokenService
 *  - SessionService
 *  - JWT refresh strategy
 *
 * ============================================================================
 */

export class RefreshTokenDto {
  /**
   * --------------------------------------------------------------------------
   * Refresh Token
   * --------------------------------------------------------------------------
   *
   * Long-lived credential used to:
   *
   *  - rotate access tokens
   *  - extend authenticated sessions
   *  - maintain stateless authentication
   *  - support secure session continuity
   */

  @IsString()
  @IsNotEmpty()
  @IsJWT()
  refreshToken: string;

  /**
   * --------------------------------------------------------------------------
   * Device Fingerprint
   * --------------------------------------------------------------------------
   *
   * Optional client fingerprint used for:
   *
   *  - session correlation
   *  - suspicious refresh detection
   *  - adaptive trust scoring
   *  - replay anomaly analysis
   */

  @IsOptional()
  @IsString()
  @MaxLength(512)
  fingerprint?: string;
}