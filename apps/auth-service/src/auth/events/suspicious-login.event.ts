// apps/auth-service/src/auth/events/suspicious-login.event.ts

import {
  ThreatClassification,
  ThreatSeverity,
} from '../../ai-security/interfaces/threat-analysis.interface';

/**
 * ============================================================================
 * ASF Suspicious Login Event
 * ============================================================================
 *
 * High-priority distributed security telemetry event emitted when
 * the authentication pipeline detects anomalous or hostile behavior.
 *
 * Core Responsibilities:
 *
 *  - suspicious authentication escalation
 *  - adaptive threat correlation
 *  - AI-assisted security telemetry
 *  - real-time fraud detection
 *  - distributed incident propagation
 *  - automated response orchestration
 *
 * Trigger Conditions:
 *
 *  - impossible travel detection
 *  - abnormal timing signatures
 *  - credential stuffing patterns
 *  - brute-force indicators
 *  - TOR / proxy abuse
 *  - automated interaction fingerprints
 *  - session hijacking anomalies
 *  - geo-behavior divergence
 *
 * Designed For:
 *
 *  - SIEM pipelines
 *  - distributed alerting systems
 *  - adaptive MFA escalation
 *  - security analytics platforms
 *  - event-driven mitigation engines
 *  - real-time incident response
 *
 * ============================================================================
 */

export class SuspiciousLoginEvent {
  /**
   * --------------------------------------------------------------------------
   * Unique Security Event Identifier
   * --------------------------------------------------------------------------
   */

  eventId: string;

  /**
   * --------------------------------------------------------------------------
   * Associated User Identifier
   * --------------------------------------------------------------------------
   */

  userId?: string;

  /**
   * --------------------------------------------------------------------------
   * Authentication Identity
   * --------------------------------------------------------------------------
   */

  email?: string;

  /**
   * --------------------------------------------------------------------------
   * Source Network Address
   * --------------------------------------------------------------------------
   */

  ip: string;

  /**
   * --------------------------------------------------------------------------
   * Device Fingerprint
   * --------------------------------------------------------------------------
   */

  fingerprint?: string;

  /**
   * --------------------------------------------------------------------------
   * HTTP User-Agent
   * --------------------------------------------------------------------------
   */

  userAgent?: string;

  /**
   * --------------------------------------------------------------------------
   * Threat Intelligence Score
   * --------------------------------------------------------------------------
   */

  riskScore: number;

  /**
   * --------------------------------------------------------------------------
   * Threat Severity Classification
   * --------------------------------------------------------------------------
   */

  severity: ThreatSeverity;

  /**
   * --------------------------------------------------------------------------
   * Threat Behavior Classification
   * --------------------------------------------------------------------------
   */

  classification: ThreatClassification;

  /**
   * --------------------------------------------------------------------------
   * Threat Detection Indicators
   * --------------------------------------------------------------------------
   */

  flags: string[];

  /**
   * --------------------------------------------------------------------------
   * Impossible Travel Indicator
   * --------------------------------------------------------------------------
   */

  impossibleTravel?: boolean;

  /**
   * --------------------------------------------------------------------------
   * Estimated Travel Velocity
   * --------------------------------------------------------------------------
   */

  estimatedVelocityKmh?: number;

  /**
   * --------------------------------------------------------------------------
   * Request Timing Delta
   * --------------------------------------------------------------------------
   */

  timingDeltaMs?: number;

  /**
   * --------------------------------------------------------------------------
   * Geo Intelligence
   * --------------------------------------------------------------------------
   */

  country?: string;

  city?: string;

  region?: string;

  /**
   * --------------------------------------------------------------------------
   * Distributed Correlation Identifier
   * --------------------------------------------------------------------------
   */

  correlationId?: string;

  /**
   * --------------------------------------------------------------------------
   * Automated Mitigation State
   * --------------------------------------------------------------------------
   */

  blocked: boolean;

  /**
   * --------------------------------------------------------------------------
   * Adaptive MFA Escalation
   * --------------------------------------------------------------------------
   */

  requiresChallenge?: boolean;

  /**
   * --------------------------------------------------------------------------
   * Security Event Timestamp
   * --------------------------------------------------------------------------
   */

  detectedAt: string;

  constructor(
    partial?: Partial<SuspiciousLoginEvent>,
  ) {
    Object.assign(this, partial);

    this.detectedAt =
      partial?.detectedAt ??
      new Date().toISOString();

    this.flags = partial?.flags ?? [];

    this.riskScore =
      partial?.riskScore ?? 0;

    this.severity =
      partial?.severity ?? 'medium';

    this.classification =
      partial?.classification ??
      'suspicious';

    this.blocked =
      partial?.blocked ?? false;
  }
}