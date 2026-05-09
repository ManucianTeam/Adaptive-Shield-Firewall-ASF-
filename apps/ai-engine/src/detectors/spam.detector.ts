// apps/ai-engine/src/detectors/spam.detector.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  PredictionInput,
} from '../ai-engine/interfaces/prediction.interface';

@Injectable()
export class SpamDetector {
  private readonly logger = new Logger(
    SpamDetector.name,
  );

  // =========================
  // MAIN DETECTOR
  // =========================

  async detect(
    input: PredictionInput,
  ): Promise<{
    isSpam: boolean;
    score: number;
    reasons: string[];
  }> {
    let score = 0;

    const reasons: string[] = [];

    // =========================
    // HIGH REQUEST RATE
    // =========================

    if ((input.requestCount || 0) > 500) {
      score += 25;

      reasons.push(
        'HIGH_REQUEST_RATE',
      );
    }

    // =========================
    // FAILED REQUESTS
    // =========================

    if ((input.failedRequests || 0) > 50) {
      score += 20;

      reasons.push(
        'FAILED_REQUEST_SPAM',
      );
    }

    // =========================
    // HIGH SUSPICIOUS SCORE
    // =========================

    if (
      (input.suspiciousScore || 0) >=
      70
    ) {
      score += 25;

      reasons.push(
        'HIGH_SUSPICIOUS_SCORE',
      );
    }

    // =========================
    // BOT ACTIVITY
    // =========================

    if (input.isBot) {
      score += 30;

      reasons.push(
        'BOT_ACTIVITY',
      );
    }

    // =========================
    // TOR / PROXY
    // =========================

    if (input.isTor) {
      score += 20;

      reasons.push(
        'TOR_TRAFFIC',
      );
    }

    if (input.isProxy) {
      score += 10;

      reasons.push(
        'PROXY_TRAFFIC',
      );
    }

    // =========================
    // BLACKLIST
    // =========================

    if ((input.blacklistHits || 0) > 0) {
      score += 40;

      reasons.push(
        'BLACKLIST_MATCH',
      );
    }

    // =========================
    // INVALID USER AGENT
    // =========================

    if (
      !input.userAgent ||
      input.userAgent.length < 10
    ) {
      score += 15;

      reasons.push(
        'INVALID_USER_AGENT',
      );
    }

    // =========================
    // NORMALIZE
    // =========================

    if (score > 100) {
      score = 100;
    }

    const isSpam = score >= 60;

    // =========================
    // LOGGING
    // =========================

    if (isSpam) {
      this.logger.warn(
        `[SPAM DETECTED] ${input.ip} => score=${score}`,
      );
    }

    return {
      isSpam,
      score,
      reasons,
    };
  }
}