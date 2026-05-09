// apps/gateway/src/ai-engine/ai-engine.service.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  AIScoreEngine,
  AIScoreInput,
} from './ai-score.engine';

import {
  ConfidenceEngine,
  ConfidenceInput,
} from './confidence.engine';

import {
  RiskScoreEngine,
  RiskScoreInput,
} from './risk-score.engine';

import {
  PredictionInput,
  PredictionResult,
} from './interfaces/prediction.interface';

import {
  ScoreResult,
  ScoreBreakdown,
} from './interfaces/score.interface';

@Injectable()
export class AIEngineService {
  private readonly logger = new Logger(AIEngineService.name);

  constructor(
    private readonly aiScoreEngine: AIScoreEngine,
    private readonly confidenceEngine: ConfidenceEngine,
    private readonly riskScoreEngine: RiskScoreEngine,
  ) {}

  async analyze(
    input: PredictionInput,
  ): Promise<PredictionResult & ScoreResult> {
    // =========================
    // AI SCORE
    // =========================

    const aiInput: AIScoreInput = {
      ip: input.ip,
      requestCount: input.requestCount,
      failedRequests: input.failedRequests,
      anomalyCount: input.anomalyCount,
      blockedCount: input.blockedCount,
      suspiciousScore: input.suspiciousScore,
      isVpn: input.isVpn,
      isTor: input.isTor,
      isProxy: input.isProxy,
      isBot: input.isBot,
      userAgent: input.userAgent,
      country: input.country,
    };

    const aiResult =
      this.aiScoreEngine.calculate(aiInput);

    // =========================
    // CONFIDENCE
    // =========================

    const confidenceInput: ConfidenceInput = {
      anomalyCount: input.anomalyCount,
      suspiciousScore: input.suspiciousScore,
      requestCount: input.requestCount,
      failedRequests: input.failedRequests,
      behaviorMatches: input.behaviorMatches,
      raceConditionDetected:
        input.raceConditionDetected,
      vpnDetected: input.isVpn,
      torDetected: input.isTor,
      botProbability: input.isBot ? 0.95 : 0.1,
    };

    const confidenceResult =
      this.confidenceEngine.calculate(
        confidenceInput,
      );

    // =========================
    // RISK SCORE
    // =========================

    const riskInput: RiskScoreInput = {
      ip: input.ip,
      requestCount: input.requestCount,
      failedRequests: input.failedRequests,
      anomalyCount: input.anomalyCount,
      blockedCount: input.blockedCount,
      suspiciousScore: input.suspiciousScore,
      isVpn: input.isVpn,
      isTor: input.isTor,
      isProxy: input.isProxy,
      isBot: input.isBot,
      raceConditionDetected:
        input.raceConditionDetected,
      blacklistHits: input.blacklistHits,
      userAgent: input.userAgent,
    };

    const riskResult =
      this.riskScoreEngine.calculate(riskInput);

    // =========================
    // FINAL PREDICTION
    // =========================

    let prediction:
      | 'safe'
      | 'suspicious'
      | 'malicious'
      | 'critical' = 'safe';

    if (riskResult.riskScore >= 85) {
      prediction = 'critical';
    } else if (riskResult.riskScore >= 65) {
      prediction = 'malicious';
    } else if (riskResult.riskScore >= 35) {
      prediction = 'suspicious';
    }

    // =========================
    // BREAKDOWN
    // =========================

    const breakdown: ScoreBreakdown[] = [
      {
        label: 'Trust Score',
        value: aiResult.trustScore,
        reason: 'AI trust analysis',
      },
      {
        label: 'Risk Score',
        value: riskResult.riskScore,
        reason: 'Threat detection analysis',
      },
      {
        label: 'Confidence Score',
        value: confidenceResult.confidence,
        reason: 'Attack confidence estimation',
      },
    ];

    // =========================
    // DETECTED PATTERNS
    // =========================

    const detectedPatterns = [
      ...aiResult.reasons,
      ...riskResult.reasons,
      ...confidenceResult.reasons,
    ];

    const uniquePatterns = [
      ...new Set(detectedPatterns),
    ];

    // =========================
    // FINAL LEVEL
    // =========================

    let level:
      | 'safe'
      | 'warning'
      | 'danger'
      | 'critical' = 'safe';

    if (riskResult.riskScore >= 80) {
      level = 'critical';
    } else if (riskResult.riskScore >= 60) {
      level = 'danger';
    } else if (riskResult.riskScore >= 30) {
      level = 'warning';
    }

    const result: PredictionResult & ScoreResult =
      {
        prediction,

        confidence:
          confidenceResult.confidence,

        confidenceScore:
          confidenceResult.confidence,

        trustScore: aiResult.trustScore,

        riskScore: riskResult.riskScore,

        level,

        shouldBlock:
          riskResult.shouldBlock,

        shouldMonitor:
          riskResult.riskScore >= 30,

        reasons: uniquePatterns,

        detectedPatterns: uniquePatterns,

        breakdown,

        calculatedAt: new Date(),

        timestamp: new Date(),
      };

    this.logger.warn(
      `[AI ENGINE] ${input.ip} => prediction=${prediction} risk=${result.riskScore}`,
    );

    return result;
  }
}