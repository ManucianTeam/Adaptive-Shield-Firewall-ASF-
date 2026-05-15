/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Request Context Interface Layer
 * File: request-context.interface.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines the normalized distributed request
 * execution context propagated throughout ASF
 * security, telemetry, and orchestration layers.
 *
 * SECURITY OBJECTIVES:
 * - Establish request execution continuity
 * - Support distributed tracing
 * - Enrich behavioral telemetry
 * - Enable adaptive risk correlation
 * - Improve forensic observability
 *
 * DESIGN PRINCIPLES:
 * - Immutable contextual propagation
 * - Lightweight serialization
 * - Zero-trust execution modeling
 * - Distributed-system compatibility
 * - High observability integration
 *
 * IMPORTANT:
 * Request context objects are transient runtime
 * execution structures and SHOULD NOT directly
 * contain sensitive secrets or raw credentials.
 *
 * NEVER:
 * - persist raw access tokens
 * - expose internal runtime state publicly
 * - trust unverified client metadata
 * - overload request context with heavy payloads
 *
 * ============================================================
 */

import { Fingerprint } from './fingerprint.interface';

/**
 * ============================================================
 * Request Identity Context
 * ============================================================
 *
 * PURPOSE:
 * Represents authenticated identity metadata
 * associated with a request execution flow.
 * ============================================================
 */

export interface RequestIdentityContext {
  userId?: string;

  sessionId?: string;

  role?: string;

  authenticated: boolean;

  authenticationMethod?: string;

  tokenVersion?: number;

  trustLevel?: number;
}

/**
 * ============================================================
 * Request Telemetry Context
 * ============================================================
 *
 * PURPOSE:
 * Represents runtime observability metadata
 * propagated across distributed services.
 * ============================================================
 */

export interface RequestTelemetryContext {
  requestId?: string;

  correlationId?: string;

  traceId?: string;

  spanId?: string;

  processingNode?: string;

  gatewayRegion?: string;

  service?: string;

  version?: string;

  receivedAt: number;
}

/**
 * ============================================================
 * Request Security Context
 * ============================================================
 *
 * PURPOSE:
 * Represents adaptive security evaluation
 * metadata associated with the request.
 * ============================================================
 */

export interface RequestSecurityContext {
  suspicious?: boolean;

  suspicionScore?: number;

  riskScore?: number;

  trustScore?: number;

  botProbability?: number;

  replayRisk?: number;

  anomalyDetected?: boolean;

  rateLimited?: boolean;

  timeoutTriggered?: boolean;

  blocked?: boolean;

  threatClassification?: string;

  mitigationStrategy?: string;
}

/**
 * ============================================================
 * Request Infrastructure Context
 * ============================================================
 *
 * PURPOSE:
 * Represents infrastructure-level metadata
 * for distributed request processing.
 * ============================================================
 */

export interface RequestInfrastructureContext {
  node?: string;

  pod?: string;

  cluster?: string;

  region?: string;

  availabilityZone?: string;

  containerId?: string;

  orchestrationPlatform?: string;
}

/**
 * ============================================================
 * Primary Request Context Contract
 * ============================================================
 *
 * PURPOSE:
 * Represents the centralized execution context
 * propagated across ASF request pipelines.
 *
 * USED BY:
 * - guards
 * - interceptors
 * - telemetry pipelines
 * - anomaly engines
 * - distributed tracing systems
 * - adaptive policy engines
 * ============================================================
 */

export interface RequestContext {
  /**
   * ==========================================================
   * Request Metadata
   * ==========================================================
   */

  method: string;

  path: string;

  protocol?: string;

  ipAddress: string;

  forwardedFor?: string[];

  userAgent?: string;

  origin?: string;

  referer?: string;

  /**
   * ==========================================================
   * Temporal Metadata
   * ==========================================================
   */

  timestamp: number;

  receivedAt: number;

  requestStartTime?: number;

  executionLatencyMs?: number;

  /**
   * ==========================================================
   * Identity Context
   * ==========================================================
   */

  identity?: RequestIdentityContext;

  /**
   * ==========================================================
   * Behavioral Fingerprint
   * ==========================================================
   */

  fingerprint?: Fingerprint;

  /**
   * ==========================================================
   * Security Context
   * ==========================================================
   */

  security?: RequestSecurityContext;

  /**
   * ==========================================================
   * Telemetry Context
   * ==========================================================
   */

  telemetry?: RequestTelemetryContext;

  /**
   * ==========================================================
   * Infrastructure Context
   * ==========================================================
   */

  infrastructure?: RequestInfrastructureContext;

  /**
   * ==========================================================
   * Request Headers Snapshot
   * ==========================================================
   *
   * IMPORTANT:
   * Sensitive headers SHOULD be filtered
   * before persistence or external export.
   * ==========================================================
   */

  headers?: Record<string, string>;

  /**
   * ==========================================================
   * Query Parameters Snapshot
   * ==========================================================
   */

  query?: Record<string, unknown>;

  /**
   * ==========================================================
   * Route Parameters Snapshot
   * ==========================================================
   */

  params?: Record<string, unknown>;

  /**
   * ==========================================================
   * Arbitrary Runtime Metadata
   * ==========================================================
   *
   * Used for:
   * - AI enrichment pipelines
   * - adaptive scoring extensions
   * - distributed orchestration metadata
   * - future telemetry integrations
   * ==========================================================
   */

  metadata?: Record<string, unknown>;
}
