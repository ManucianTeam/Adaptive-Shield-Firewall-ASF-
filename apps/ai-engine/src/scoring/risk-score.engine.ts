// apps/gateway/src/ai-engine/risk-score.engine.ts

import { Injectable, Logger } from '@nestjs/common';

export interface RiskScoreInput {
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

  raceConditionDetected?: boolean;

  blacklistHits?: number;

  userAgent?: string;
}

export interface RiskScoreResult {
  riskScore: number;

  level: 'low' | 'medium' | 'high' | 'critical';

  shouldBlock: boolean;

  reasons: string[];
}

@Injectable()
export class RiskScoreEngine {
  private readonly logger = new Logger(RiskScoreEngine.name);

  calculate(input: RiskScoreInput): RiskScoreResult {
    let riskScore = 0;

    const reasons: string[] = [];

    // =========================
    // REQUEST VOLUME
    // =========================

    if ((input.requestCount || 0) > 1000) {
      riskScore += 25;

      reasons.push('EXTREME_REQUEST_VOLUME');
    } else if ((input.requestCount || 0) > 500) {
      riskScore += 15;

      reasons.push('HIGH_REQUEST_VOLUME');
    }

    // =========================
    // FAILED REQUESTS
    // =========================

    if ((input.failedRequests || 0) > 100) {
      riskScore += 20;

      reasons.push('FAILED_REQUEST_SPAM');
    }

    // =========================
    // ANOMALIES
    // =========================

    if ((input.anomalyCount || 0) > 10) {
      riskScore += 30;

      reasons.push('MULTIPLE_ANOMALIES');
    }

    if ((input.blockedCount || 0) > 5) {
      riskScore += 25;

      reasons.push('MULTIPLE_BLOCK_EVENTS');
    }

    // =========================
    // SUSPICIOUS SCORE
    // =========================

    if ((input.suspiciousScore || 0) >= 80) {
      riskScore += 35;

      reasons.push('VERY_SUSPICIOUS_BEHAVIOR');
    } else if ((input.suspiciousScore || 0) >= 60) {
      riskScore += 20;

      reasons.push('SUSPICIOUS_BEHAVIOR');
    }

    // =========================
    // NETWORK ANALYSIS
    // =========================

    if (input.isVpn) {
      riskScore += 10;

      reasons.push('VPN_DETECTED');
    }

    if (input.isProxy) {
      riskScore += 15;

      reasons.push('PROXY_DETECTED');
    }

    if (input.isTor) {
      riskScore += 35;

      reasons.push('TOR_EXIT_NODE');
    }

    // =========================
    // BOT DETECTION
    // =========================

    if (input.isBot) {
      riskScore += 40;

      reasons.push('BOT_ACTIVITY');
    }

    // =========================
    // RACE CONDITION
    // =========================

    if (input.raceConditionDetected) {
      riskScore += 30;

      reasons.push('RACE_CONDITION_ATTACK');
    }

    // =========================
    // BLACKLIST
    // =========================

    if ((input.blacklistHits || 0) > 0) {
      riskScore += 50;

      reasons.push('BLACKLIST_MATCH');
    }

    // =========================
    // USER AGENT VALIDATION
    // =========================

    if (
      !input.userAgent ||
      input.userAgent.length < 12
    ) {
      riskScore += 15;

      reasons.push('INVALID_USER_AGENT');
    }

    // =========================
    // NORMALIZE
    // =========================

    if (riskScore > 100) {
      riskScore = 100;
    }

    // =========================
    // LEVEL
    // =========================

    let level: RiskScoreResult['level'] = 'low';

    if (riskScore >= 80) {
      level = 'critical';
    } else if (riskScore >= 60) {
      level = 'high';
    } else if (riskScore >= 30) {
      level = 'medium';
    }

    // =========================
    // BLOCK DECISION
    // =========================

    const shouldBlock = riskScore >= 75;

    this.logger.warn(
      `[RISK SCORE] ${input.ip} => risk=${riskScore} level=${level}`,
    );

    return {
      riskScore,
      level,
      shouldBlock,
      reasons,
    };
  }
}