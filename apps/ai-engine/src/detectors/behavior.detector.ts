// apps/ai-engine/src/detectors/behavior.detector.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  PredictionInput,
} from '../ai-engine/interfaces/prediction.interface';

@Injectable()
export class BehaviorDetector {
  private readonly logger = new Logger(
    BehaviorDetector.name,
  );

  // =========================
  // MAIN DETECTOR
  // =========================

  async detect(
    input: PredictionInput,
  ): Promise<string[]> {
    const patterns: string[] = [];

    // =========================
    // RAPID REQUESTS
    // =========================

    if ((input.requestCount || 0) > 500) {
      patterns.push(
        'RAPID_REQUEST_PATTERN',
      );
    }

    // =========================
    // FAILED REQUEST ABUSE
    // =========================

    if ((input.failedRequests || 0) > 50) {
      patterns.push(
        'FAILED_REQUEST_ABUSE',
      );
    }

    // =========================
    // BOT ACTIVITY
    // =========================

    if (input.isBot) {
      patterns.push(
        'BOT_BEHAVIOR_PATTERN',
      );
    }

    // =========================
    // VPN / TOR / PROXY
    // =========================

    if (input.isTor) {
      patterns.push(
        'TOR_NETWORK_PATTERN',
      );
    }

    if (input.isVpn) {
      patterns.push(
        'VPN_NETWORK_PATTERN',
      );
    }

    if (input.isProxy) {
      patterns.push(
        'PROXY_NETWORK_PATTERN',
      );
    }

    // =========================
    // RACE CONDITION
    // =========================

    if (
      input.raceConditionDetected
    ) {
      patterns.push(
        'RACE_CONDITION_PATTERN',
      );
    }

    // =========================
    // BLACKLIST
    // =========================

    if ((input.blacklistHits || 0) > 0) {
      patterns.push(
        'BLACKLISTED_SOURCE_PATTERN',
      );
    }

    // =========================
    // HIGH CONFIDENCE
    // =========================

    if (
      (input.confidenceScore || 0) >=
      80
    ) {
      patterns.push(
        'HIGH_CONFIDENCE_ATTACK_PATTERN',
      );
    }

    // =========================
    // HIGH RISK SCORE
    // =========================

    if ((input.riskScore || 0) >= 80) {
      patterns.push(
        'HIGH_RISK_PATTERN',
      );
    }

    // =========================
    // INVALID USER AGENT
    // =========================

    if (
      !input.userAgent ||
      input.userAgent.length < 10
    ) {
      patterns.push(
        'INVALID_USER_AGENT_PATTERN',
      );
    }

    // =========================
    // LOGGING
    // =========================

    if (patterns.length > 0) {
      this.logger.warn(
        `[BEHAVIOR] ${input.ip} => ${patterns.join(
          ', ',
        )}`,
      );
    }

    return patterns;
  }
}