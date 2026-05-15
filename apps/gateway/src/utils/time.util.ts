/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Time Intelligence Utility
 * File: time.util.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides centralized high-precision time utilities
 * for distributed security systems and telemetry
 * pipelines.
 *
 * This utility handles:
 * - UTC normalization
 * - timestamp generation
 * - duration calculations
 * - expiration validation
 * - time window analysis
 * - drift detection
 * - secure timing helpers
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Prevent replay timing abuse
 * - Support distributed consistency
 * - Harden token expiration validation
 * - Enable accurate telemetry correlation
 * - Reduce timing desynchronization risk
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Stateless deterministic utilities
 * - UTC-first architecture
 * - Millisecond precision
 * - Lightweight execution
 * - Cloud-native compatibility
 *
 * ============================================================
 *
 * IMPORTANT:
 * Time synchronization is probabilistic
 * in distributed systems.
 *
 * NEVER:
 * - trust client-provided timestamps
 * - assume zero clock drift
 * - use local timezone for security logic
 * - expose internal timing tolerances
 *
 * ============================================================
 */

/**
 * ============================================================
 * Time Window Result
 * ============================================================
 */

export interface TimeWindowResult {
  valid: boolean;

  ageMs: number;

  remainingMs: number;

  expired: boolean;
}

/**
 * ============================================================
 * Drift Analysis Result
 * ============================================================
 */

export interface DriftResult {
  driftMs: number;

  acceptable: boolean;

  direction: 'AHEAD' | 'BEHIND' | 'SYNC';
}

/**
 * ============================================================
 * Time Utility
 * ============================================================
 */

export class TimeUtil {
  /**
   * ==========================================================
   * Default Drift Tolerance
   * ==========================================================
   */

  private static readonly DEFAULT_DRIFT_TOLERANCE = 30_000; // 30 seconds

  /**
   * ==========================================================
   * Current UTC Timestamp
   * ==========================================================
   */

  static now(): number {
    return Date.now();
  }

  /**
   * ==========================================================
   * Current ISO Timestamp
   * ==========================================================
   */

  static iso(): string {
    return new Date().toISOString();
  }

  /**
   * ==========================================================
   * UNIX Timestamp (seconds)
   * ==========================================================
   */

  static unix(): number {
    return Math.floor(Date.now() / 1000);
  }

  /**
   * ==========================================================
   * Add Milliseconds
   * ==========================================================
   */

  static addMilliseconds(ms: number): number {
    return Date.now() + ms;
  }

  /**
   * ==========================================================
   * Add Seconds
   * ==========================================================
   */

  static addSeconds(seconds: number): number {
    return Date.now() + seconds * 1000;
  }

  /**
   * ==========================================================
   * Add Minutes
   * ==========================================================
   */

  static addMinutes(minutes: number): number {
    return Date.now() + minutes * 60 * 1000;
  }

  /**
   * ==========================================================
   * Add Hours
   * ==========================================================
   */

  static addHours(hours: number): number {
    return Date.now() + hours * 60 * 60 * 1000;
  }

  /**
   * ==========================================================
   * Add Days
   * ==========================================================
   */

  static addDays(days: number): number {
    return Date.now() + days * 24 * 60 * 60 * 1000;
  }

  /**
   * ==========================================================
   * Check Expiration
   * ==========================================================
   */

  static isExpired(timestamp: number): boolean {
    return Date.now() > timestamp;
  }

  /**
   * ==========================================================
   * Duration Since Timestamp
   * ==========================================================
   */

  static durationSince(timestamp: number): number {
    return Math.max(0, Date.now() - timestamp);
  }

  /**
   * ==========================================================
   * Duration Until Timestamp
   * ==========================================================
   */

  static durationUntil(timestamp: number): number {
    return Math.max(0, timestamp - Date.now());
  }

  /**
   * ==========================================================
   * Validate Time Window
   * ==========================================================
   */

  static validateWindow(
    timestamp: number,

    ttlMs: number,
  ): TimeWindowResult {
    const now = Date.now();

    const ageMs = now - timestamp;

    const remainingMs = ttlMs - ageMs;

    const expired = remainingMs <= 0;

    return {
      valid: !expired,

      ageMs,

      remainingMs: Math.max(0, remainingMs),

      expired,
    };
  }

  /**
   * ==========================================================
   * Drift Detection
   * ==========================================================
   */

  static analyzeDrift(
    remoteTimestamp: number,

    toleranceMs = this.DEFAULT_DRIFT_TOLERANCE,
  ): DriftResult {
    const local = Date.now();

    const driftMs = remoteTimestamp - local;

    const acceptable = Math.abs(driftMs) <= toleranceMs;

    let direction: 'AHEAD' | 'BEHIND' | 'SYNC' = 'SYNC';

    if (driftMs > 0) {
      direction = 'AHEAD';
    } else if (driftMs < 0) {
      direction = 'BEHIND';
    }

    return {
      driftMs,

      acceptable,

      direction,
    };
  }

  /**
   * ==========================================================
   * Safe Sleep Utility
   * ==========================================================
   */

  static async sleep(ms: number): Promise<void> {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * ==========================================================
   * High Resolution Timer
   * ==========================================================
   */

  static highResolution(): bigint {
    return process.hrtime.bigint();
  }

  /**
   * ==========================================================
   * Measure Async Execution
   * ==========================================================
   */

  static async measure<T>(callback: () => Promise<T>): Promise<{
    result: T;

    durationMs: number;
  }> {
    const start = performance.now();

    const result = await callback();

    const end = performance.now();

    return {
      result,

      durationMs: end - start,
    };
  }

  /**
   * ==========================================================
   * Convert Milliseconds
   * ==========================================================
   */

  static toSeconds(ms: number): number {
    return ms / 1000;
  }

  static toMinutes(ms: number): number {
    return ms / (1000 * 60);
  }

  static toHours(ms: number): number {
    return ms / (1000 * 60 * 60);
  }

  /**
   * ==========================================================
   * Format Duration
   * ==========================================================
   */

  static formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);

    const minutes = Math.floor(seconds / 60);

    const hours = Math.floor(minutes / 60);

    const remainingSeconds = seconds % 60;

    const remainingMinutes = minutes % 60;

    if (hours > 0) {
      return `${hours}h ${remainingMinutes}m ${remainingSeconds}s`;
    }

    if (minutes > 0) {
      return `${minutes}m ${remainingSeconds}s`;
    }

    return `${seconds}s`;
  }

  /**
   * ==========================================================
   * Constant-Time Timestamp Compare
   * ==========================================================
   *
   * Mitigates:
   * - timing analysis
   * - naive equality leaks
   * ==========================================================
   */

  static secureCompare(
    a: number,

    b: number,
  ): boolean {
    const aStr = String(a);

    const bStr = String(b);

    if (aStr.length !== bStr.length) {
      return false;
    }

    let result = 0;

    for (let i = 0; i < aStr.length; i++) {
      result |= aStr.charCodeAt(i) ^ bStr.charCodeAt(i);
    }

    return result === 0;
  }
}
