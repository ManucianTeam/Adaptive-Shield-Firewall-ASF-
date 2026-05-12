import { Injectable, Logger } from '@nestjs/common';

export interface TimingAnalysisInput {
  userId?: string;

  ip: string;

  route: string;

  method: string;

  currentTimestamp: number;

  previousTimestamp?: number;

  averageRequestIntervalMs?: number;

  requestBurstCount?: number;

  sessionDurationMs?: number;

  typingLatencyMs?: number;

  interactionLatencyMs?: number;

  repeatedTimingPattern?: boolean;

  knownTimingProfile?: boolean;
}

export interface TimingAnalysisResult {
  score: number;

  classification:
    | 'human'
    | 'suspicious'
    | 'automated'
    | 'hostile';

  flags: string[];

  requiresMitigation: boolean;

  metadata: {
    analyzedAt: string;
    timingConfidence: number;
    timingDeltaMs?: number;
  };
}

/**
 * ============================================================================
 * ASF AI Security — Timing Analyzer
 * ============================================================================
 *
 * High-frequency behavioral timing intelligence engine responsible for
 * identifying automated interaction signatures, deterministic request
 * intervals, burst-based abuse patterns, and non-human temporal behavior.
 *
 * This analyzer focuses on:
 *
 *  - request interval consistency
 *  - ultra-low latency automation signatures
 *  - repetitive timing sequences
 *  - burst traffic anomalies
 *  - interaction realism validation
 *  - timing entropy evaluation
 *
 * The implementation is intentionally deterministic, lightweight,
 * and suitable for real-time authentication and API security pipelines.
 *
 * Future evolution may integrate:
 *
 *  - probabilistic timing models
 *  - recurrent temporal embeddings
 *  - adaptive entropy learning
 *  - distributed timing reputation systems
 *  - sequence-aware AI threat scoring
 *
 * ============================================================================
 */

@Injectable()
export class TimingAnalyzer {
  private readonly logger = new Logger(
    TimingAnalyzer.name,
  );

  /**
   * --------------------------------------------------------------------------
   * Main Timing Analysis
   * --------------------------------------------------------------------------
   */

  analyze(
    input: TimingAnalysisInput,
  ): TimingAnalysisResult {
    let score = 100;

    const flags: string[] = [];

    let timingDeltaMs: number | undefined;

    // ------------------------------------------------------------------------
    // Direct Request Interval Analysis
    // ------------------------------------------------------------------------

    if (
      input.previousTimestamp !== undefined
    ) {
      timingDeltaMs =
        input.currentTimestamp -
        input.previousTimestamp;

      if (timingDeltaMs < 25) {
        score -= 45;

        flags.push(
          'extremely_low_request_interval',
        );
      } else if (timingDeltaMs < 75) {
        score -= 30;

        flags.push(
          'non_human_request_frequency',
        );
      } else if (timingDeltaMs < 150) {
        score -= 15;

        flags.push(
          'suspicious_request_timing',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Average Request Interval Analysis
    // ------------------------------------------------------------------------

    if (
      input.averageRequestIntervalMs !==
      undefined
    ) {
      if (
        input.averageRequestIntervalMs < 120
      ) {
        score -= 20;

        flags.push(
          'abnormally_consistent_intervals',
        );
      }

      if (
        input.averageRequestIntervalMs > 30000
      ) {
        score -= 5;

        flags.push(
          'high_idle_session_behavior',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Burst Activity Detection
    // ------------------------------------------------------------------------

    if (
      input.requestBurstCount !== undefined
    ) {
      if (input.requestBurstCount > 40) {
        score -= 15;

        flags.push(
          'high_frequency_request_burst',
        );
      }

      if (input.requestBurstCount > 120) {
        score -= 30;

        flags.push(
          'extreme_request_flood_pattern',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Typing Latency Analysis
    // ------------------------------------------------------------------------

    if (input.typingLatencyMs !== undefined) {
      if (input.typingLatencyMs < 15) {
        score -= 20;

        flags.push(
          'inhuman_typing_latency',
        );
      }

      if (input.typingLatencyMs > 5000) {
        score -= 5;

        flags.push(
          'abnormal_input_latency',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Interaction Latency Analysis
    // ------------------------------------------------------------------------

    if (
      input.interactionLatencyMs !== undefined
    ) {
      if (
        input.interactionLatencyMs < 10
      ) {
        score -= 25;

        flags.push(
          'instantaneous_interaction_pattern',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Deterministic Timing Pattern Detection
    // ------------------------------------------------------------------------

    if (input.repeatedTimingPattern) {
      score -= 20;

      flags.push(
        'deterministic_timing_signature',
      );
    }

    // ------------------------------------------------------------------------
    // Known Timing Trust Profile
    // ------------------------------------------------------------------------

    if (input.knownTimingProfile === false) {
      score -= 10;

      flags.push(
        'unknown_timing_behavior_profile',
      );
    }

    // ------------------------------------------------------------------------
    // Long Session Temporal Drift
    // ------------------------------------------------------------------------

    if (
      input.sessionDurationMs !== undefined
    ) {
      const hours =
        input.sessionDurationMs /
        1000 /
        60 /
        60;

      if (hours > 24) {
        score -= 10;

        flags.push(
          'extended_session_duration',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Score Normalization
    // ------------------------------------------------------------------------

    const normalizedScore = Math.max(
      0,
      Math.min(100, score),
    );

    // ------------------------------------------------------------------------
    // Timing Classification
    // ------------------------------------------------------------------------

    let classification:
      | 'human'
      | 'suspicious'
      | 'automated'
      | 'hostile' = 'human';

    if (normalizedScore < 20) {
      classification = 'hostile';
    } else if (normalizedScore < 45) {
      classification = 'automated';
    } else if (normalizedScore < 75) {
      classification = 'suspicious';
    }

    // ------------------------------------------------------------------------
    // Mitigation Escalation
    // ------------------------------------------------------------------------

    const requiresMitigation =
      normalizedScore < 50;

    // ------------------------------------------------------------------------
    // Structured Security Logging
    // ------------------------------------------------------------------------

    this.logger.warn({
      message:
        'Timing analysis completed',

      userId: input.userId,

      ip: input.ip,

      route: input.route,

      method: input.method,

      score: normalizedScore,

      classification,

      requiresMitigation,

      timingDeltaMs,

      flags,
    });

    return {
      score: normalizedScore,

      classification,

      flags,

      requiresMitigation,

      metadata: {
        analyzedAt:
          new Date().toISOString(),

        timingConfidence:
          normalizedScore / 100,

        timingDeltaMs,
      },
    };
  }
}