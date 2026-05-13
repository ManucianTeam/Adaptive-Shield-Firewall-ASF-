// apps/auth-service/src/auth/interfaces/session.interface.ts

/**
 * ============================================================================
 * ASF Session Interface
 * ============================================================================
 *
 * Canonical distributed session contract used by the ASF
 * authentication and adaptive security infrastructure.
 *
 * Core Responsibilities:
 *
 *  - session persistence
 *  - distributed authentication state
 *  - refresh-token correlation
 *  - device trust tracking
 *  - adaptive risk telemetry
 *  - Zero Trust session orchestration
 *
 * Designed For:
 *
 *  - Redis-backed session stores
 *  - distributed microservices
 *  - horizontally scaled gateways
 *  - adaptive authentication pipelines
 *  - AI-assisted security analysis
 *
 * Security Characteristics:
 *
 *  - stateless JWT correlation
 *  - device fingerprint binding
 *  - session revocation compatibility
 *  - replay mitigation readiness
 *  - multi-device identity isolation
 *
 * ============================================================================
 */

export interface SessionInterface {
  /**
   * --------------------------------------------------------------------------
   * Session Identifier
   * --------------------------------------------------------------------------
   *
   * Globally unique authentication session ID.
   */

  sessionId: string;

  /**
   * --------------------------------------------------------------------------
   * User Identifier
   * --------------------------------------------------------------------------
   */

  userId: string;

  /**
   * --------------------------------------------------------------------------
   * Account Email
   * --------------------------------------------------------------------------
   */

  email: string;

  /**
   * --------------------------------------------------------------------------
   * Refresh Token Hash
   * --------------------------------------------------------------------------
   *
   * Securely hashed refresh token used for:
   *
   *  - session continuation
   *  - token rotation validation
   *  - replay protection
   *  - revocation workflows
   */

  refreshTokenHash: string;

  /**
   * --------------------------------------------------------------------------
   * Authorization Roles
   * --------------------------------------------------------------------------
   */

  roles: string[];

  /**
   * --------------------------------------------------------------------------
   * Client Device Fingerprint
   * --------------------------------------------------------------------------
   */

  fingerprint?: string;

  /**
   * --------------------------------------------------------------------------
   * Human-Readable Device Name
   * --------------------------------------------------------------------------
   */

  deviceName?: string;

  /**
   * --------------------------------------------------------------------------
   * Source Network Address
   * --------------------------------------------------------------------------
   */

  ipAddress?: string;

  /**
   * --------------------------------------------------------------------------
   * HTTP User-Agent
   * --------------------------------------------------------------------------
   */

  userAgent?: string;

  /**
   * --------------------------------------------------------------------------
   * Distributed Trust Score
   * --------------------------------------------------------------------------
   */

  trustScore?: number;

  /**
   * --------------------------------------------------------------------------
   * Adaptive Security Risk Score
   * --------------------------------------------------------------------------
   */

  riskScore?: number;

  /**
   * --------------------------------------------------------------------------
   * Session Status
   * --------------------------------------------------------------------------
   */

  status:
    | 'active'
    | 'revoked'
    | 'expired'
    | 'suspicious'
    | 'blocked';

  /**
   * --------------------------------------------------------------------------
   * Multi-Factor Authentication State
   * --------------------------------------------------------------------------
   */

  mfaVerified?: boolean;

  /**
   * --------------------------------------------------------------------------
   * Last Activity Timestamp
   * --------------------------------------------------------------------------
   */

  lastActivityAt: string;

  /**
   * --------------------------------------------------------------------------
   * Session Creation Timestamp
   * --------------------------------------------------------------------------
   */

  createdAt: string;

  /**
   * --------------------------------------------------------------------------
   * Session Expiration Timestamp
   * --------------------------------------------------------------------------
   */

  expiresAt: string;

  /**
   * --------------------------------------------------------------------------
   * Revocation Timestamp
   * --------------------------------------------------------------------------
   */

  revokedAt?: string;

  /**
   * --------------------------------------------------------------------------
   * Distributed Correlation Identifier
   * --------------------------------------------------------------------------
   */

  correlationId?: string;

  /**
   * --------------------------------------------------------------------------
   * Additional Security Metadata
   * --------------------------------------------------------------------------
   */

  metadata?: Record<string, unknown>;
}