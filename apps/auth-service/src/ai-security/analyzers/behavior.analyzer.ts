import { Injectable, Logger } from '@nestjs/common';

export interface BehaviorAnalysisInput {
  userId?: string;

  ip: string;

  fingerprint?: string;

  userAgent?: string;

  route: string;

  method: string;

  requestTimestamp: number;

  previousRequestTimestamp?: number;

  typingSpeedMs?: number;

  mouseMovementEntropy?: number;

  navigationPattern?: string[];

  sessionRequestCount?: number;

  repeatedActions?: number;

  knownBehaviorProfile?: boolean;
}

export interface BehaviorAnalysisResult {
  score: number;

  trustLevel:
    | 'trusted'
    | 'normal'
    | 'suspicious'
    | 'hostile';

  flags: string[];

  requiresChallenge: boolean;

  metadata: {
    analyzedAt: string;
    behavioralConfidence: number;
  };
}

/**
 * ============================================================================
 * ASF AI Security — Behavior Analyzer
 * ============================================================================
 *
 * Advanced behavioral intelligence engine responsible for evaluating
 * interaction consistency, navigation entropy, timing realism,
 * automation fingerprints, and behavioral trust continuity.
 *
 * The analyzer simulates a lightweight adaptive trust engine capable of:
 *
 *  - detecting scripted interaction patterns
 *  - identifying timing anomalies
 *  - recognizing repetitive automation behavior
 *  - evaluating behavioral entropy
 *  - validating interaction realism
 *  - tracking trust continuity across sessions
 *
 * The implementation is intentionally deterministic and low-latency,
 * making it suitable for real-time authentication pipelines and
 * distributed edge security gateways.
 *
 * Future iterations may integrate:
 *
 *  - recurrent behavioral embeddings
 *  - reinforcement trust adaptation
 *  - federated behavioral learning
 *  - biometric interaction profiling
 *  - graph-based session intelligence
 *
 * ============================================================================
 */

@Injectable()
export class BehaviorAnalyzer {
  private readonly logger = new Logger(
    BehaviorAnalyzer.name,
  );

  /**
   * --------------------------------------------------------------------------
   * Main Behavioral Analysis
   * --------------------------------------------------------------------------
   */

  analyze(
    input: BehaviorAnalysisInput,
  ): BehaviorAnalysisResult {
    let score = 100;

    const flags: string[] = [];

    // ------------------------------------------------------------------------
    // Request Timing Analysis
    // ------------------------------------------------------------------------

    if (
      input.previousRequestTimestamp !== undefined
    ) {
      const delta =
        input.requestTimestamp -
        input.previousRequestTimestamp;

      if (delta < 100) {
        score -= 25;

        flags.push(
          'inhuman_request_timing_detected',
        );
      }

      if (delta < 40) {
        score -= 35;

        flags.push(
          'automation_speed_signature',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Typing Pattern Analysis
    // ------------------------------------------------------------------------

    if (input.typingSpeedMs !== undefined) {
      if (input.typingSpeedMs < 20) {
        score -= 20;

        flags.push(
          'typing_speed_anomaly',
        );
      }

      if (input.typingSpeedMs > 3000) {
        score -= 5;

        flags.push(
          'abnormally_slow_interaction',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Mouse Entropy Analysis
    // ------------------------------------------------------------------------

    if (
      input.mouseMovementEntropy !== undefined
    ) {
      if (input.mouseMovementEntropy < 0.15) {
        score -= 20;

        flags.push(
          'low_entropy_pointer_behavior',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Navigation Pattern Analysis
    // ------------------------------------------------------------------------

    if (input.navigationPattern) {
      const repeatedRoutes =
        this.detectRepeatedNavigation(
          input.navigationPattern,
        );

      if (repeatedRoutes >= 3) {
        score -= 15;

        flags.push(
          'repetitive_navigation_pattern',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Session Flood Analysis
    // ------------------------------------------------------------------------

    if (
      input.sessionRequestCount !== undefined
    ) {
      if (input.sessionRequestCount > 250) {
        score -= 15;

        flags.push(
          'high_session_request_volume',
        );
      }

      if (input.sessionRequestCount > 600) {
        score -= 30;

        flags.push(
          'extreme_session_activity',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Repeated Action Analysis
    // ------------------------------------------------------------------------

    if (input.repeatedActions !== undefined) {
      if (input.repeatedActions > 8) {
        score -= 18;

        flags.push(
          'repeated_action_pattern',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Trust Continuity Analysis
    // ------------------------------------------------------------------------

    if (input.knownBehaviorProfile === false) {
      score -= 10;

      flags.push(
        'unknown_behavioral_profile',
      );
    }

    // ------------------------------------------------------------------------
    // Score Normalization
    // ------------------------------------------------------------------------

    const normalizedScore = Math.max(
      0,
      Math.min(100, score),
    );

    // ------------------------------------------------------------------------
    // Behavioral Trust Classification
    // ------------------------------------------------------------------------

    let trustLevel:
      | 'trusted'
      | 'normal'
      | 'suspicious'
      | 'hostile' = 'trusted';

    if (normalizedScore < 25) {
      trustLevel = 'hostile';
    } else if (normalizedScore < 50) {
      trustLevel = 'suspicious';
    } else if (normalizedScore < 80) {
      trustLevel = 'normal';
    }

    // ------------------------------------------------------------------------
    // Challenge Escalation
    // ------------------------------------------------------------------------

    const requiresChallenge =
      normalizedScore < 45;

    // ------------------------------------------------------------------------
    // Security Telemetry Logging
    // ------------------------------------------------------------------------

    this.logger.warn({
      message:
        'Behavioral analysis completed',

      userId: input.userId,

      ip: input.ip,

      route: input.route,

      method: input.method,

      score: normalizedScore,

      trustLevel,

      requiresChallenge,

      flags,
    });

    return {
      score: normalizedScore,

      trustLevel,

      flags,

      requiresChallenge,

      metadata: {
        analyzedAt:
          new Date().toISOString(),

        behavioralConfidence:
          normalizedScore / 100,
      },
    };
  }

  /**
   * --------------------------------------------------------------------------
   * Repetitive Navigation Detection
   * --------------------------------------------------------------------------
   */

  private detectRepeatedNavigation(
    routes: string[],
  ): number {
    const counter = new Map<string, number>();

    for (const route of routes) {
      counter.set(
        route,
        (counter.get(route) || 0) + 1,
      );
    }

    let repeated = 0;

    for (const [, count] of counter.entries()) {
      if (count >= 3) {
        repeated++;
      }
    }

    return repeated;
  }
}
