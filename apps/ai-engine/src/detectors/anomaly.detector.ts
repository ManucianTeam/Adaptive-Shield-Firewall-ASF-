// apps/ai-engine/src/detectors/anomaly.detector.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  PredictionInput,
} from '../ai-engine/interfaces/prediction.interface';

@Injectable()
export class AnomalyDetector {
  private readonly logger = new Logger(
    AnomalyDetector.name,
  );

  // =========================
  // MAIN DETECTOR
  // =========================

  async detect(
    input: PredictionInput,
  ): Promise<string[]> {
    const anomalies: string[] = [];

    // =========================
    // REQUEST FLOOD
    // =========================

    if ((input.requestCount || 0) > 1000) {
      anomalies.push(
        'REQUEST_FLOOD_DETECTED',
      );
    }

    // =========================
    // FAILED REQUEST SPAM
    // =========================

    if ((input.failedRequests || 0) > 100) {
      anomalies.push(
        'FAILED_REQUEST_SPAM',
      );
    }

    // =========================
    // HIGH SUSPICIOUS SCORE
    // =========================

    if (
      (input.suspiciousScore || 0) >= 80
    ) {
      anomalies.push(
        'HIGH_SUSPICIOUS_ACTIVITY',
      );
    }

    // =========================
    // VPN / TOR / PROXY
    // =========================

    if (input.isTor) {
      anomalies.push(
        'TOR_TRAFFIC_DETECTED',
      );
    }

    if (input.isVpn) {
      anomalies.push(
        'VPN_TRAFFIC_DETECTED',
      );
    }

    if (input.isProxy) {
      anomalies.push(
        'PROXY_TRAFFIC_DETECTED',
      );
    }

    // =========================
    // BOT DETECTION
    // =========================

    if (input.isBot) {
      anomalies.push(
        'BOT_ACTIVITY_DETECTED',
      );
    }

    // =========================
    // RACE CONDITION
    // =========================

    if (
      input.raceConditionDetected
    ) {
      anomalies.push(
        'RACE_CONDITION_ATTACK',
      );
    }

    // =========================
    // BLACKLIST
    // =========================

    if ((input.blacklistHits || 0) > 0) {
      anomalies.push(
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
      anomalies.push(
        'INVALID_USER_AGENT',
      );
    }

    // =========================
    // LOGGING
    // =========================

    if (anomalies.length > 0) {
      this.logger.warn(
        `[ANOMALY] ${input.ip} => ${anomalies.join(
          ', ',
        )}`,
      );
    }

    return anomalies;
  }
}