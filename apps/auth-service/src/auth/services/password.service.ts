// apps/auth-service/src/auth/services/password.service.ts

import {
  BadRequestException,
  Injectable,
  Logger,
} from '@nestjs/common';

import * as bcrypt from 'bcrypt';

import { randomBytes } from 'crypto';

/**
 * ============================================================================
 * ASF Password Security Service
 * ============================================================================
 *
 * Enterprise-grade credential security service engineered for adaptive
 * authentication infrastructures and Zero Trust identity systems.
 *
 * Core Responsibilities:
 *
 *  - password hashing
 *  - credential verification
 *  - entropy validation
 *  - password-policy enforcement
 *  - secure reset-token generation
 *  - credential hardening
 *
 * Security Architecture:
 *
 *  - bcrypt adaptive hashing
 *  - timing-safe validation
 *  - entropy-aware password analysis
 *  - brute-force resistance
 *  - replay mitigation readiness
 *  - cryptographically secure randomness
 *
 * Designed For:
 *
 *  - distributed authentication systems
 *  - high-security API gateways
 *  - enterprise IAM platforms
 *  - adaptive access-control infrastructures
 *  - AI-assisted threat mitigation
 *
 * ============================================================================
 */

@Injectable()
export class PasswordService
{
  private readonly logger = new Logger(
    PasswordService.name,
  );

  /**
   * --------------------------------------------------------------------------
   * BCrypt Computational Cost
   * --------------------------------------------------------------------------
   */

  private readonly SALT_ROUNDS =
    12;

  /**
   * --------------------------------------------------------------------------
   * Password Hashing Pipeline
   * --------------------------------------------------------------------------
   */

  async hash(
    password: string,
  ): Promise<string> {
    /**
     * ------------------------------------------------------------------------
     * Password Policy Enforcement
     * ------------------------------------------------------------------------
     */

    this.validateStrength(
      password,
    );

    /**
     * ------------------------------------------------------------------------
     * Adaptive BCrypt Hashing
     * ------------------------------------------------------------------------
     */

    const hash =
      await bcrypt.hash(
        password,
        this.SALT_ROUNDS,
      );

    this.logger.debug({
      event:
        'password_hashed',
    });

    return hash;
  }

  /**
   * --------------------------------------------------------------------------
   * Password Verification Pipeline
   * --------------------------------------------------------------------------
   */

  async compare(
    plain: string,
    hashed: string,
  ): Promise<boolean> {
    const valid =
      await bcrypt.compare(
        plain,
        hashed,
      );

    this.logger.debug({
      event:
        'password_verified',

      valid,
    });

    return valid;
  }

  /**
   * --------------------------------------------------------------------------
   * Password Strength Validation
   * --------------------------------------------------------------------------
   */

  validateStrength(
    password: string,
  ): void {
    /**
     * ------------------------------------------------------------------------
     * Length Validation
     * ------------------------------------------------------------------------
     */

    if (
      password.length < 10
    ) {
      throw new BadRequestException(
        'Password must contain at least 10 characters',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Complexity Validation
     * ------------------------------------------------------------------------
     */

    const hasUppercase =
      /[A-Z]/.test(
        password,
      );

    const hasLowercase =
      /[a-z]/.test(
        password,
      );

    const hasNumber =
      /[0-9]/.test(
        password,
      );

    const hasSpecial =
      /[^A-Za-z0-9]/.test(
        password,
      );

    if (
      !hasUppercase ||
      !hasLowercase ||
      !hasNumber ||
      !hasSpecial
    ) {
      throw new BadRequestException(
        'Password must contain uppercase, lowercase, numeric, and special characters',
      );
    }

    /**
     * ------------------------------------------------------------------------
     * Entropy Heuristic
     * ------------------------------------------------------------------------
     */

    const entropy =
      this.calculateEntropy(
        password,
      );

    if (
      entropy < 50
    ) {
      throw new BadRequestException(
        'Password entropy is too weak',
      );
    }
  }

  /**
   * --------------------------------------------------------------------------
   * Shannon-like Entropy Estimation
   * --------------------------------------------------------------------------
   */

  calculateEntropy(
    password: string,
  ): number {
    let charsetSize = 0;

    if (/[a-z]/.test(password)) {
      charsetSize += 26;
    }

    if (/[A-Z]/.test(password)) {
      charsetSize += 26;
    }

    if (/[0-9]/.test(password)) {
      charsetSize += 10;
    }

    if (/[^A-Za-z0-9]/.test(password)) {
      charsetSize += 32;
    }

    return Math.log2(
      Math.pow(
        charsetSize,
        password.length,
      ),
    );
  }

  /**
   * --------------------------------------------------------------------------
   * Secure Password Reset Token
   * --------------------------------------------------------------------------
   */

  generateResetToken(): string {
    const token =
      randomBytes(48).toString(
        'hex',
      );

    this.logger.debug({
      event:
        'password_reset_token_generated',
    });

    return token;
  }

  /**
   * --------------------------------------------------------------------------
   * Password Exposure Heuristic
   * --------------------------------------------------------------------------
   */

  isWeakCommonPassword(
    password: string,
  ): boolean {
    const weakPasswords = [
      'password',
      '123456',
      'qwerty',
      'admin',
      'letmein',
      'password123',
      '123456789',
      'welcome',
    ];

    return weakPasswords.includes(
      password.toLowerCase(),
    );
  }

  /**
   * --------------------------------------------------------------------------
   * Credential Rotation Recommendation
   * --------------------------------------------------------------------------
   */

  shouldRotatePassword(
    updatedAt: Date,
  ): boolean {
    const maxAgeDays =
      90;

    const diff =
      Date.now() -
      updatedAt.getTime();

    const ageDays =
      diff /
      (1000 * 60 * 60 * 24);

    return (
      ageDays >= maxAgeDays
    );
  }
}