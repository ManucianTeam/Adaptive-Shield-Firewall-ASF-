// apps/gateway/src/ai-engine/ai-score.engine.ts

import { Injectable, Logger } from '@nestjs/common';

export interface AIScoreInput {
  ip: string;
  requestCount?: number;
  failedRequests?: number;
  anomalyCount?: number;
  blockedCount?: number;
  suspiciousScore?: number;
  isVpn?: boolean;
  isTor?: boolean;
  isProxy?: boolean;
  isBot?: boolean;
  country?: string;
  userAgent?: string;
}

export interface AIScoreResult {
  trustScore: number;
  riskScore: number;
  status: 'safe' | 'warning' | 'danger' | 'critical';
  reasons: string[];
}

@Injectable()
export class AIScoreEngine {
  private readonly logger = new Logger(AIScoreEngine.name);

  calculate(input: AIScoreInput): AIScoreResult {
    let trustScore = 100;
    let riskScore = 0;

    const reasons: string[] = [];

    // =========================
    // REQUEST ANALYSIS
    // =========================

    if ((input.requestCount || 0) > 500) {
      riskScore += 25;
      trustScore -= 20;

      reasons.push('HIGH_REQUEST_VOLUME');
    }

    if ((input.failedRequests || 0) > 50) {
      riskScore += 20;
      trustScore -= 15;

      reasons.push('TOO_MANY_FAILED_REQUESTS');
    }

    // =========================
    // ANOMALY ANALYSIS
    // =========================

    if ((input.anomalyCount || 0) > 10) {
      riskScore += 30;
      trustScore -= 25;

      reasons.push('MULTIPLE_ANOMALIES');
    }

    if ((input.blockedCount || 0) > 5) {
      riskScore += 40;
      trustScore -= 30;

      reasons.push('MULTIPLE_BLOCK_EVENTS');
    }

    // =========================
    // SUSPICIOUS SCORE
    // =========================

    if ((input.suspiciousScore || 0) >= 70) {
      riskScore += 35;
      trustScore -= 30;

      reasons.push('HIGH_SUSPICIOUS_SCORE');
    }

    // =========================
    // NETWORK CHECK
    // =========================

    if (input.isVpn) {
      riskScore += 10;
      trustScore -= 5;

      reasons.push('VPN_DETECTED');
    }

    if (input.isTor) {
      riskScore += 30;
      trustScore -= 20;

      reasons.push('TOR_DETECTED');
    }

    if (input.isProxy) {
      riskScore += 15;
      trustScore -= 10;

      reasons.push('PROXY_DETECTED');
    }

    // =========================
    // BOT DETECTION
    // =========================

    if (input.isBot) {
      riskScore += 50;
      trustScore -= 40;

      reasons.push('BOT_ACTIVITY_DETECTED');
    }

    // =========================
    // USER AGENT CHECK
    // =========================

    if (
      !input.userAgent ||
      input.userAgent.length < 10
    ) {
      riskScore += 20;
      trustScore -= 15;

      reasons.push('INVALID_USER_AGENT');
    }

    // =========================
    // NORMALIZE
    // =========================

    if (trustScore < 0) {
      trustScore = 0;
    }

    if (riskScore > 100) {
      riskScore = 100;
    }

    // =========================
    // STATUS
    // =========================

    let status: AIScoreResult['status'] = 'safe';

    if (riskScore >= 80) {
      status = 'critical';
    } else if (riskScore >= 60) {
      status = 'danger';
    } else if (riskScore >= 30) {
      status = 'warning';
    }

    this.logger.warn(
      `[AI SCORE] ${input.ip} => risk=${riskScore} trust=${trustScore}`,
    );

    return {
      trustScore,
      riskScore,
      status,
      reasons,
    };
  }
}