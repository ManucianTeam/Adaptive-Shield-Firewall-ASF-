/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Secure Redemption DTO Layer
 * File: redeem.dto.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines the inbound payload contract for
 * secure redemption-based transactional flows.
 *
 * TARGET USE CASES:
 * - Voucher redemption
 * - Reward claiming
 * - Promo activation
 * - Gift-code execution
 * - Tokenized benefit exchange
 *
 * SECURITY OBJECTIVES:
 * - Replay attack mitigation
 * - Payload normalization
 * - Idempotent transaction enforcement
 * - Abuse prevention
 * - Distributed request correlation
 *
 * DESIGN PRINCIPLES:
 * - Strict validation boundaries
 * - Explicit trust minimization
 * - Lightweight validation overhead
 * - Security-first request contracts
 *
 * ============================================================
 */

import {
  IsAlphanumeric,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

import { Transform } from 'class-transformer';

/**
 * ============================================================
 * Redeem DTO
 * ============================================================
 *
 * SECURITY NOTES:
 * - Redemption codes are normalized
 * - Idempotency support prevents replay execution
 * - Device correlation supports anomaly detection
 * - Correlation identifiers improve forensic tracing
 * ============================================================
 */

export class RedeemDto {
  /**
   * ============================================================
   * Redemption Code
   * ============================================================
   *
   * PURPOSE:
   * Primary redeemable asset identifier.
   *
   * SECURITY:
   * - Uppercase normalization
   * - Whitespace stripping
   * - Alphanumeric enforcement
   * - Length restrictions reduce abuse surface
   * ============================================================
   */

  @IsString()
  @IsNotEmpty()
  @IsAlphanumeric()
  @Length(6, 64)
  @Transform(({ value }) =>
    typeof value === 'string' ? value.trim().toUpperCase() : value,
  )
  code: string;

  /**
   * ============================================================
   * Idempotency Key
   * ============================================================
   *
   * PURPOSE:
   * Prevents duplicate redemption execution
   * during retries or race-condition scenarios.
   *
   * SECURITY:
   * - Required for distributed-safe operations
   * - Must remain unique per transaction attempt
   * ============================================================
   */

  @IsString()
  @IsNotEmpty()
  @MinLength(16)
  @MaxLength(128)
  idempotencyKey: string;

  /**
   * ============================================================
   * Device Identifier
   * ============================================================
   *
   * PURPOSE:
   * Supports behavioral continuity analysis
   * and suspicious activity correlation.
   *
   * EXAMPLES:
   * - Device hash
   * - Browser fingerprint ID
   * - Mobile installation identifier
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
   * Optional client-provided fingerprint signal.
   *
   * SECURITY WARNING:
   * Client-side fingerprints should NEVER
   * be trusted as authoritative identity data.
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @MaxLength(512)
  fingerprint?: string;

  /**
   * ============================================================
   * Redemption Context
   * ============================================================
   *
   * PURPOSE:
   * Optional contextual metadata
   * attached to redemption operations.
   *
   * USED FOR:
   * - Campaign attribution
   * - Risk correlation
   * - Behavioral segmentation
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @MaxLength(128)
  context?: string;

  /**
   * ============================================================
   * Correlation Identifier
   * ============================================================
   *
   * PURPOSE:
   * Distributed tracing and forensic tracking.
   *
   * USED FOR:
   * - Security telemetry
   * - Audit pipelines
   * - Incident investigation
   * - Cross-service correlation
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @Matches(/^[a-zA-Z0-9-_]+$/)
  @MaxLength(128)
  correlationId?: string;
}
