// apps/auth-service/src/auth/dto/register.dto.ts

import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

/**
 * ============================================================================
 * ASF Register DTO
 * ============================================================================
 *
 * Registration payload validation contract responsible for:
 *
 *  - identity validation
 *  - credential integrity enforcement
 *  - malformed payload rejection
 *  - account creation normalization
 *  - adaptive security readiness
 *
 * Security Characteristics:
 *
 *  - strict credential constraints
 *  - password complexity enforcement
 *  - fingerprint-aware onboarding
 *  - distributed identity compatibility
 *  - AI-assisted risk analysis readiness
 *
 * Integrated With:
 *
 *  - AuthController
 *  - AuthService
 *  - UsersService
 *  - password hashing subsystem
 *  - adaptive onboarding pipeline
 *
 * ============================================================================
 */

export class RegisterDto {
  /**
   * --------------------------------------------------------------------------
   * User Display Name
   * --------------------------------------------------------------------------
   *
   * Public-facing account identifier.
   */

  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(50)
  username: string;

  /**
   * --------------------------------------------------------------------------
   * User Email Address
   * --------------------------------------------------------------------------
   *
   * Primary identity and recovery channel.
   */

  @IsString()
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(255)
  email: string;

  /**
   * --------------------------------------------------------------------------
   * Account Password
   * --------------------------------------------------------------------------
   *
   * Strong credential validated against
   * security complexity requirements.
   */

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(128)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/,
    {
      message:
        'Password must contain uppercase, lowercase, and numeric characters',
    },
  )
  password: string;

  /**
   * --------------------------------------------------------------------------
   * Optional Device Fingerprint
   * --------------------------------------------------------------------------
   *
   * Used for:
   *
   *  - adaptive trust initialization
   *  - fraud correlation
   *  - distributed device telemetry
   *  - onboarding anomaly detection
   */

  @IsOptional()
  @IsString()
  @MaxLength(512)
  fingerprint?: string;

  /**
   * --------------------------------------------------------------------------
   * Client Device Name
   * --------------------------------------------------------------------------
   *
   * Optional human-readable device descriptor.
   */

  @IsOptional()
  @IsString()
  @MaxLength(255)
  deviceName?: string;
}