// apps/auth-service/src/auth/events/login-attempt.event.ts

import {
  ThreatClassification,
  ThreatSeverity,
} from '../../ai-security/interfaces/threat-analysis.interface';

/**
 * ============================================================================
 * ASF Login Attempt Event
 * ============================================================================
 *
 * Distributed authentication telemetry event emitted during
 * every authentication attempt across the ASF security pipeline.
 *
 * Primary Responsibilities:
 *
 *  - authentication observability
 *  - threat correlation
 *  - anomaly telemetry streaming
 *  - adaptive risk enrichment
 *  - distributed audit tracking
 *  - behavioral intelligence aggregation
 *
 * Event Sources:
 *
 *  - AuthService
 *  - gateway middleware
 *  - suspicious activity detectors
 *  - AI-assisted authentication analyzers
 *
 * Designed For:
 *
 *  - Kafka / NATS event streaming
 *  - SIEM ingestion
 *  - distributed analytics
 *  - security dashboards
 *  - real-time threat monitoring
 *
 * ============================================================================
 */

export class LoginAttemptEvent {
  /**
   * --------------------------------------------------------------------------
   * Unique Event Identifier
   * --------------------------------------------------------------------------
   */

  eventId: string;

  /**
   * --------------------------------------------------------------------------
   * Authentication Identity
   * --------------------------------------------------------------------------
   */

  email: string;

  /**
   * --------------------------------------------------------------------------
   * User Identifier
   * --------------------------------------------------------------------------
   */

  userId?: string;

  /**
   * --------------------------------------------------------------------------
   * Source Network Address
   * --------------------------------------------------------------------------
   */

  ip: string;

  /**
   * --------------------------------------------------------------------------
   * Client User-Agent
   * --------------------------------------------------------------------------
   */

  userAgent?: string;

  /**
   * --------------------------------------------------------------------------
   * Device Fingerprint
   * --------------------------------------------------------------------------
   */

  fingerprint?: string;

  /**
   * --------------------------------------------------------------------------
   * Authentication Success State
   * --------------------------------------------------------------------------
   */

  success: boolean;

  /**
   * --------------------------------------------------------------------------
   * Threat Intelligence Score
   * --------------------------------------------------------------------------
   */

  riskScore: number;

  /**
   * --------------------------------------------------------------------------
   * Threat Severity
   * --------------------------------------------------------------------------
   */

  severity: ThreatSeverity;

  /**
   * --------------------------------------------------------------------------
   * Threat Classification
   * --------------------------------------------------------------------------
   */

  classification: ThreatClassification;

  /**
   * --------------------------------------------------------------------------
   * Threat Indicators
   * --------------------------------------------------------------------------
   */

  flags: string[];

  /**
   * --------------------------------------------------------------------------
   * Geo Intelligence
   * --------------------------------------------------------------------------
   */

  country?: string;

  city?: string;

  /**
   * --------------------------------------------------------------------------
   * Session Correlation
   * --------------------------------------------------------------------------
   */

  sessionId?: string;

  /**
   * --------------------------------------------------------------------------
   * Distributed Correlation Identifier
   * --------------------------------------------------------------------------
   */

  correlationId?: string;

  /**
   * --------------------------------------------------------------------------
   * Authentication Timestamp
   * --------------------------------------------------------------------------
   */

  createdAt: string;

  constructor(
    partial?: Partial<LoginAttemptEvent>,
  ) {
    Object.assign(this, partial);

    this.createdAt =
      partial?.createdAt ??
      new Date().toISOString();

    this.flags = partial?.flags ?? [];

    this.riskScore =
      partial?.riskScore ?? 0;

    this.severity =
      partial?.severity ?? 'low';

    this.classification =
      partial?.classification ??
      'normal';
  }
}