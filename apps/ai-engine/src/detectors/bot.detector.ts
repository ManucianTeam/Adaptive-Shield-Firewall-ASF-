// apps/ai-engine/src/detectors/bot.detector.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  PredictionInput,
} from '../ai-engine/interfaces/prediction.interface';

@Injectable()
export class BotDetector {
  private readonly logger = new Logger(
    BotDetector.name,
  );

  // =========================
  // BOT KEYWORDS
  // =========================

  private readonly botKeywords = [
    'bot',
    'crawler',
    'spider',
    'scraper',
    'curl',
    'wget',
    'python',
    'axios',
    'postman',
    'httpclient',
    'headless',
    'selenium',
    'playwright',
    'puppeteer',
  ];

  // =========================
  // MAIN DETECTOR
  // =========================

  async detect(
    input: PredictionInput,
  ): Promise<{
    isBot: boolean;
    confidence: number;
    reasons: string[];
  }> {
    let confidence = 0;

    const reasons: string[] = [];

    const userAgent = (
      input.userAgent || ''
    ).toLowerCase();

    // =========================
    // USER AGENT CHECK
    // =========================

    for (const keyword of this
      .botKeywords) {
      if (userAgent.includes(keyword)) {
        confidence += 25;

        reasons.push(
          `BOT_KEYWORD_${keyword.toUpperCase()}`,
        );
      }
    }

    // =========================
    // REQUEST VOLUME
    // =========================

    if ((input.requestCount || 0) > 1000) {
      confidence += 20;

      reasons.push(
        'EXTREME_REQUEST_VOLUME',
      );
    }

    // =========================
    // FAILED REQUESTS
    // =========================

    if ((input.failedRequests || 0) > 100) {
      confidence += 15;

      reasons.push(
        'FAILED_REQUEST_SPAM',
      );
    }

    // =========================
    // SUSPICIOUS SCORE
    // =========================

    if (
      (input.suspiciousScore || 0) >=
      80
    ) {
      confidence += 25;

      reasons.push(
        'HIGH_SUSPICIOUS_SCORE',
      );
    }

    // =========================
    // TOR / PROXY
    // =========================

    if (input.isTor) {
      confidence += 20;

      reasons.push(
        'TOR_NETWORK_DETECTED',
      );
    }

    if (input.isProxy) {
      confidence += 10;

      reasons.push(
        'PROXY_DETECTED',
      );
    }

    // =========================
    // INVALID USER AGENT
    // =========================

    if (
      !input.userAgent ||
      input.userAgent.length < 10
    ) {
      confidence += 30;

      reasons.push(
        'INVALID_USER_AGENT',
      );
    }

    // =========================
    // NORMALIZE
    // =========================

    if (confidence > 100) {
      confidence = 100;
    }

    const isBot = confidence >= 60;

    // =========================
    // LOGGING
    // =========================

    if (isBot) {
      this.logger.warn(
        `[BOT DETECTED] ${input.ip} => confidence=${confidence}`,
      );
    }

    return {
      isBot,
      confidence,
      reasons,
    };
  }
}