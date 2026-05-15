/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Secure Transaction DTO Layer
 * File: transaction.dto.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines validated transactional payload contracts
 * for high-integrity financial and security-sensitive
 * operations processed through ASF.
 *
 * TARGET SYSTEMS:
 * - Payment gateways
 * - Financial transfer pipelines
 * - Reward distribution systems
 * - Internal settlement services
 * - Secure transactional APIs
 *
 * SECURITY OBJECTIVES:
 * - Replay attack mitigation
 * - Distributed-safe transaction execution
 * - Payload integrity enforcement
 * - Concurrency conflict reduction
 * - Behavioral telemetry enrichment
 * - Fraud prevention support
 *
 * DESIGN PRINCIPLES:
 * - Strict validation boundaries
 * - Explicit transaction constraints
 * - Deterministic request structures
 * - Minimal trust assumptions
 * - Low-overhead validation path
 *
 * ============================================================
 */

import {
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsPositive,
  IsString,
  Length,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
} from 'class-validator';

import { Transform, Type } from 'class-transformer';

/**
 * ============================================================
 * Transaction DTO
 * ============================================================
 *
 * SECURITY NOTES:
 * - Amount validation reduces malformed transfers
 * - Idempotency support prevents replay execution
 * - Correlation metadata supports forensic tracing
 * - Device continuity improves anomaly detection
 * ============================================================
 */

export class TransactionDto {
  /**
   * ============================================================
   * Transaction Amount
   * ============================================================
   *
   * PURPOSE:
   * Represents transactional monetary value.
   *
   * SECURITY:
   * - Positive-only values
   * - Upper-bound restriction
   * - Numeric coercion control
   *
   * NOTE:
   * High-value thresholds should additionally
   * trigger adaptive risk escalation.
   * ============================================================
   */

  @Type(() => Number)
  @IsNumber({
    maxDecimalPlaces: 2,
  })
  @IsPositive()
  @Min(0.01)
  @Max(100000000)
  amount: number;

  /**
   * ============================================================
   * Currency Code
   * ============================================================
   *
   * PURPOSE:
   * ISO-style currency identifier.
   *
   * SECURITY:
   * - Uppercase normalization
   * - Fixed-length validation
   * - Prevent malformed currency injection
   * ============================================================
   */

  @IsString()
  @IsNotEmpty()
  @Length(3, 3)
  @Transform(({ value }) =>
    typeof value === 'string' ? value.trim().toUpperCase() : value,
  )
  currency: string;

  /**
   * ============================================================
   * Target Account Identifier
   * ============================================================
   *
   * PURPOSE:
   * Destination transactional entity reference.
   *
   * SECURITY:
   * - Restricted character set
   * - Length-bound enforcement
   * - Normalized formatting
   * ============================================================
   */

  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  @MaxLength(128)
  @Matches(/^[a-zA-Z0-9._:-]+$/)
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  targetAccount: string;

  /**
   * ============================================================
   * Idempotency Key
   * ============================================================
   *
   * PURPOSE:
   * Prevents duplicate transactional execution
   * caused by retries, race conditions,
   * or distributed replay attempts.
   *
   * REQUIRED FOR:
   * - Financial consistency
   * - Distributed-safe execution
   * - Replay attack mitigation
   * ============================================================
   */

  @IsString()
  @IsNotEmpty()
  @MinLength(16)
  @MaxLength(128)
  idempotencyKey: string;

  /**
   * ============================================================
   * Transaction Reference
   * ============================================================
   *
   * PURPOSE:
   * External or client-visible transaction identifier.
   *
   * USED FOR:
   * - Reconciliation
   * - Audit systems
   * - Customer support tracing
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @MaxLength(128)
  @Matches(/^[a-zA-Z0-9-_]+$/)
  reference?: string;

  /**
   * ============================================================
   * Device Identifier
   * ============================================================
   *
   * PURPOSE:
   * Behavioral continuity correlation.
   *
   * USED FOR:
   * - Fraud analysis
   * - Session continuity
   * - Adaptive risk scoring
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
   * Lightweight client-side fingerprint signal.
   *
   * SECURITY WARNING:
   * Never trust client-provided fingerprints
   * as authoritative identity signals.
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @MaxLength(512)
  fingerprint?: string;

  /**
   * ============================================================
   * Correlation Identifier
   * ============================================================
   *
   * PURPOSE:
   * Enables distributed request tracing
   * and security telemetry aggregation.
   *
   * USED FOR:
   * - Audit logging
   * - Incident investigation
   * - SIEM pipelines
   * - Cross-service observability
   * ============================================================
   */

  @IsOptional()
  @IsString()
  @Matches(/^[a-zA-Z0-9-_]+$/)
  @MaxLength(128)
  correlationId?: string;
}
