// apps/auth-service/src/auth/dto/forgot-password.dto.ts

import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
} from 'class-validator';

/**
 * ============================================================================
 * ASF Forgot Password DTO
 * ============================================================================
 *
 * Data transfer object responsible for validating
 * password recovery initiation requests.
 *
 * Security Objectives:
 *
 *  - strict email validation
 *  - malformed input rejection
 *  - payload normalization readiness
 *  - abuse surface reduction
 *  - recovery workflow integrity
 *
 * Integrated With:
 *
 *  - AuthController
 *  - AuthService
 *  - password recovery pipelines
 *  - email verification systems
 *  - adaptive security middleware
 *
 * ============================================================================
 */

export class ForgotPasswordDto {
  /**
   * --------------------------------------------------------------------------
   * User Email Address
   * --------------------------------------------------------------------------
   *
   * Primary recovery identifier used to:
   *
   *  - locate account ownership
   *  - generate recovery tokens
   *  - initiate reset workflows
   *  - trigger security notifications
   */

  @IsString()
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(255)
  email: string;
}