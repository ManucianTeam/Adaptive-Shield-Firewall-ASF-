/* ============================================================
 * ASF AI Engine
 * Race Condition Intelligence Model
 * File: race.model.ts
 * ============================================================
 *
 * PURPOSE:
 * Defines canonical distributed concurrency and
 * race-condition intelligence structures used by
 * the ASF runtime protection engine.
 *
 * This model standardizes:
 * - concurrent execution telemetry
 * - distributed lock intelligence
 * - replay/race attack detection
 * - transaction collision analysis
 * - synchronization anomaly reporting
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Detect replay race attacks
 * - Identify concurrent mutation abuse
 * - Protect distributed critical sections
 * - Harden async execution paths
 * - Support adaptive mitigation systems
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Deterministic structures
 * - Distributed-system compatibility
 * - Lightweight serialization
 * - AI-ready telemetry pipelines
 * - Explainable concurrency intelligence
 *
 * ============================================================
 *
 * IMPORTANT:
 * Race detection is probabilistic in distributed
 * environments with network latency and eventual
 * consistency.
 *
 * NEVER:
 * - assume perfect synchronization
 * - trust client ordering guarantees
 * - expose internal lock topology
 * - hard-fail solely on timing anomalies
 *
 * ============================================================
 */

/**
 * ============================================================
 * Race Threat Type
 * ============================================================
 */

export enum RaceThreatType {
  NONE = 'NONE',

  REPLAY_ATTACK = 'REPLAY_ATTACK',

  DOUBLE_SPEND = 'DOUBLE_SPEND',

  CONCURRENT_MUTATION = 'CONCURRENT_MUTATION',

  SESSION_COLLISION = 'SESSION_COLLISION',

  DISTRIBUTED_RACE = 'DISTRIBUTED_RACE',

  LOCK_BYPASS = 'LOCK_BYPASS',
}

/**
 * ============================================================
 * Execution State
 * ============================================================
 */

export enum ExecutionState {
  PENDING = 'PENDING',

  RUNNING = 'RUNNING',

  COMPLETED = 'COMPLETED',

  FAILED = 'FAILED',

  TIMED_OUT = 'TIMED_OUT',

  ABORTED = 'ABORTED',
}

/**
 * ============================================================
 * Lock Strategy
 * ============================================================
 */

export enum LockStrategy {
  NONE = 'NONE',

  OPTIMISTIC = 'OPTIMISTIC',

  PESSIMISTIC = 'PESSIMISTIC',

  DISTRIBUTED_REDIS = 'DISTRIBUTED_REDIS',

  QUORUM = 'QUORUM',
}

/**
 * ============================================================
 * Concurrency Metrics
 * ============================================================
 */

export interface ConcurrencyMetrics {
  concurrentExecutions: number;

  executionWindowMs: number;

  averageLatencyMs: number;

  lockWaitTimeMs: number;

  retryCount: number;

  collisionProbability: number;

  contentionScore: number;
}

/**
 * ============================================================
 * Execution Context
 * ============================================================
 */

export interface ExecutionContext {
  executionId: string;

  entityId: string;

  resourceId: string;

  operation: string;

  nodeId: string;

  processId: number;

  startedAt: number;

  completedAt?: number;
}

/**
 * ============================================================
 * Lock Metadata
 * ============================================================
 */

export interface LockMetadata {
  strategy: LockStrategy;

  lockKey: string;

  acquired: boolean;

  acquiredAt?: number;

  expiresAt?: number;

  ownerId?: string;

  contentionDetected: boolean;
}

/**
 * ============================================================
 * Race Indicators
 * ============================================================
 */

export interface RaceIndicators {
  replayDetected: boolean;

  duplicateMutation: boolean;

  abnormalConcurrency: boolean;

  lockContention: boolean;

  distributedCollision: boolean;

  outOfOrderExecution: boolean;

  staleWriteDetected: boolean;
}

/**
 * ============================================================
 * Race Analysis Result
 * ============================================================
 */

export interface RaceAnalysis {
  analysisId: string;

  threatType: RaceThreatType;

  executionState: ExecutionState;

  riskScore: number;

  confidence: number;

  blocked: boolean;

  trusted: boolean;

  indicators: string[];

  metrics: ConcurrencyMetrics;

  context: ExecutionContext;

  lock: LockMetadata;

  telemetry?: Record<string, unknown>;

  analyzedAt: number;
}

/**
 * ============================================================
 * Distributed Event
 * ============================================================
 */

export interface DistributedEvent {
  eventId: string;

  sourceNode: string;

  resourceId: string;

  operation: string;

  timestamp: number;

  sequence?: number;

  metadata?: Record<string, unknown>;
}

/**
 * ============================================================
 * Race Detection Thresholds
 * ============================================================
 */

export const RACE_THRESHOLDS = {
  LOW: 0.25,

  MEDIUM: 0.5,

  HIGH: 0.75,

  CRITICAL: 0.9,
} as const;

/**
 * ============================================================
 * Race Model Factory
 * ============================================================
 */

export class RaceModelFactory {
  /**
   * ==========================================================
   * Empty Concurrency Metrics
   * ==========================================================
   */

  static emptyMetrics(): ConcurrencyMetrics {
    return {
      concurrentExecutions: 0,

      executionWindowMs: 0,

      averageLatencyMs: 0,

      lockWaitTimeMs: 0,

      retryCount: 0,

      collisionProbability: 0,

      contentionScore: 0,
    };
  }

  /**
   * ==========================================================
   * Default Lock Metadata
   * ==========================================================
   */

  static emptyLock(): LockMetadata {
    return {
      strategy: LockStrategy.NONE,

      lockKey: '',

      acquired: false,

      contentionDetected: false,
    };
  }

  /**
   * ==========================================================
   * Create Execution Context
   * ==========================================================
   */

  static createContext(
    entityId: string,

    resourceId: string,

    operation: string,
  ): ExecutionContext {
    return {
      executionId: crypto.randomUUID(),

      entityId,

      resourceId,

      operation,

      nodeId: process.env.NODE_ID || 'node-unknown',

      processId: process.pid,

      startedAt: Date.now(),
    };
  }

  /**
   * ==========================================================
   * Create Default Race Analysis
   * ==========================================================
   */

  static createDefault(
    entityId: string,

    resourceId: string,

    operation: string,
  ): RaceAnalysis {
    return {
      analysisId: crypto.randomUUID(),

      threatType: RaceThreatType.NONE,

      executionState: ExecutionState.PENDING,

      riskScore: 0,

      confidence: 0,

      blocked: false,

      trusted: true,

      indicators: [],

      metrics: this.emptyMetrics(),

      context: this.createContext(entityId, resourceId, operation),

      lock: this.emptyLock(),

      analyzedAt: Date.now(),
    };
  }
}
