// apps/gateway/src/ai-engine/confidence.engine.ts

import { Injectable, Logger } from '@nestjs/common';

export interface ConfidenceInput {
  anomalyCount?: number;
  suspiciousScore?: number;
  requestCount?: number;
  failedRequests?: number;
  behaviorMatches?: number;
  botProbability?: number;
  raceConditionDetected?: boolean;
  vpnDetected?: boolean;
  torDetected?: boolean;
}

export interface ConfidenceResult {
  confidence: number;
  level: 'low' | 'medium' | 'high' | 'critical';
  reasons: string[];
}

@Injectable()
export class ConfidenceEngine {
  private readonly logger = new Logger(ConfidenceEngine.name);

  calculate(input: ConfidenceInput): ConfidenceResult {
    let confidence = 0;

    const reasons: string[] = [];

    // =========================
    // ANOMALY CHECK
    // =========================

    if ((input.anomalyCount || 0) >= 5) {
      confidence += 20;

      reasons.push('MULTIPLE_ANOMALIES');
    }

    // =========================
    // SUSPICIOUS SCORE
    // =========================

    if ((input.suspiciousScore || 0) >= 70) {
      confidence += 25;

      reasons.push('HIGH_SUSPICIOUS_SCORE');
    }

    // =========================
    // REQUEST SPAM
    // =========================

    if ((input.requestCount || 0) >= 500) {
      confidence += 15;

      reasons.push('REQUEST_SPAM_PATTERN');
    }

    // =========================
    // FAILED REQUESTS
    // =========================

    if ((input.failedRequests || 0) >= 50) {
      confidence += 15;

      reasons.push('HIGH_FAILED_REQUESTS');
    }

    // =========================
    // BEHAVIOR MATCH
    // =========================

    if ((input.behaviorMatches || 0) >= 3) {
      confidence += 20;

      reasons.push('KNOWN_ATTACK_PATTERN');
    }

    // =========================
    // BOT DETECTION
    // =========================

    if ((input.botProbability || 0) >= 0.8) {
      confidence += 35;

      reasons.push('BOT_CONFIDENCE_HIGH');
    }

    // =========================
    // RACE CONDITION
    // =========================

    if (input.raceConditionDetected) {
      confidence += 30;

      reasons.push('RACE_CONDITION_DETECTED');
    }

    // =========================
    // NETWORK CHECK
    // =========================

    if (input.vpnDetected) {
      confidence += 5;

      reasons.push('VPN_DETECTED');
    }

    if (input.torDetected) {
      confidence += 20;

      reasons.push('TOR_DETECTED');
    }

    // =========================
    // NORMALIZE
    // =========================

    if (confidence > 100) {
      confidence = 100;
    }

    // =========================
    // LEVEL
    // =========================

    let level: ConfidenceResult['level'] = 'low';

    if (confidence >= 80) {
      level = 'critical';
    } else if (confidence >= 60) {
      level = 'high';
    } else if (confidence >= 30) {
      level = 'medium';
    }

    this.logger.warn(
      `[CONFIDENCE] confidence=${confidence} level=${level}`,
    );

    return {
      confidence,
      level,
      reasons,
    };
  }
}