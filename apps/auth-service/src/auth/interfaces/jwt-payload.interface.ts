// apps/auth-service/src/auth/interfaces/jwt-payload.interface.ts

/**
 * ============================================================================
 * ASF JWT Payload Interface
 * ============================================================================
 *
 * Canonical authentication identity contract embedded inside
 * signed JWT access tokens and refresh tokens.
 *
 * Core Responsibilities:
 *
 *  - stateless identity propagation
 *  - distributed authorization context
 *  - session correlation
 *  - RBAC compatibility
 *  - adaptive trust enrichment
 *  - Zero Trust authentication support
 *
 * Security Design Goals:
 *
 *  - deterministic payload structure
 *  - minimal token surface area
 *  - cryptographic integrity support
 *  - horizontally scalable identity transport
 *  - gateway-compatible authorization metadata
 *
 * Integrated With:
 *
 *  - JwtStrategy
 *  - RefreshStrategy
 *  - JwtAuthGuard
 *  - RolesGuard
 *  - TokenService
 *  - distributed API gateways
 *
 * ============================================================================
 */

export interface JwtPayload {
  /**
   * --------------------------------------------------------------------------
   * Subject Identifier
   * --------------------------------------------------------------------------
   *
   * Canonical authenticated user identifier.
   */

  sub: string;

  /**
   * --------------------------------------------------------------------------
   * Account Email
   * --------------------------------------------------------------------------
   *
   * Primary authentication identity.
   */

  email: string;

  /**
   * --------------------------------------------------------------------------
   * Authorization Roles
   * --------------------------------------------------------------------------
   *
   * Distributed RBAC context used for:
   *
   *  - endpoint authorization
   *  - gateway policy enforcement
   *  - adaptive privilege validation
   */

  roles: string[];

  /**
   * --------------------------------------------------------------------------
   * Session Identifier
   * --------------------------------------------------------------------------
   *
   * Correlates JWTs with distributed session storage.
   */

  sessionId: string;

  /**
   * --------------------------------------------------------------------------
   * Device Fingerprint
   * --------------------------------------------------------------------------
   *
   * Optional adaptive security telemetry.
   */

  fingerprint?: string;

  /**
   * --------------------------------------------------------------------------
   * Token Issuer
   * --------------------------------------------------------------------------
   */

  iss?: string;

  /**
   * --------------------------------------------------------------------------
   * Token Audience
   * --------------------------------------------------------------------------
   */

  aud?: string;

  /**
   * --------------------------------------------------------------------------
   * Issued Timestamp
   * --------------------------------------------------------------------------
   */

  iat?: number;

  /**
   * --------------------------------------------------------------------------
   * Expiration Timestamp
   * --------------------------------------------------------------------------
   */

  exp?: number;

  /**
   * --------------------------------------------------------------------------
   * Not-Before Timestamp
   * --------------------------------------------------------------------------
   */

  nbf?: number;

  /**
   * --------------------------------------------------------------------------
   * JWT Identifier
   * --------------------------------------------------------------------------
   *
   * Unique token correlation identifier.
   */

  jti?: string;

  /**
   * --------------------------------------------------------------------------
   * Distributed Trust Level
   * --------------------------------------------------------------------------
   */

  trustLevel?: number;

  /**
   * --------------------------------------------------------------------------
   * AI Security Risk Score
   * --------------------------------------------------------------------------
   */

  riskScore?: number;
}