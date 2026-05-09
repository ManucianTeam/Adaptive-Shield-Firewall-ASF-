// apps/gateway/src/ai-engine/detection.service.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  PredictionInput,
  PredictionResult,
} from './interfaces/prediction.interface';

import {
  AIEngineService,
} from './ai-engine.service';

@Injectable()
export class DetectionService {
  private readonly logger = new Logger(
    DetectionService.name,
  );

  constructor(
    private readonly aiEngineService: AIEngineService,
  ) {}

  // =========================
  // MAIN DETECTION
  // =========================

  async detect(
    input: PredictionInput,
  ): Promise<PredictionResult> {
    const result =
      await this.aiEngineService.analyze(
        input,
      );

    // =========================
    // LOGGING
    // =========================

    if (result.shouldBlock) {
      this.logger.error(
        `[BLOCKED] ${input.ip} => ${result.prediction}`,
      );
    } else if (result.shouldMonitor) {
      this.logger.warn(
        `[MONITOR] ${input.ip} => ${result.prediction}`,
      );
    } else {
      this.logger.log(
        `[SAFE] ${input.ip}`,
      );
    }

    return {
      prediction: result.prediction,

      confidence: result.confidence,

      riskScore: result.riskScore,

      shouldBlock: result.shouldBlock,

      shouldMonitor: result.shouldMonitor,

      reasons: result.reasons,

      detectedPatterns:
        result.detectedPatterns,

      timestamp: result.timestamp,
    };
  }

  // =========================
  // QUICK BOT CHECK
  // =========================

  async isBot(
    input: PredictionInput,
  ): Promise<boolean> {
    const result =
      await this.detect(input);

    return (
      result.prediction === 'malicious' ||
      result.prediction === 'critical'
    );
  }

  // =========================
  // QUICK BLOCK CHECK
  // =========================

  async shouldBlock(
    input: PredictionInput,
  ): Promise<boolean> {
    const result =
      await this.detect(input);

    return result.shouldBlock;
  }

  // =========================
  // QUICK RISK CHECK
  // =========================

  async getRiskLevel(
    input: PredictionInput,
  ): Promise<string> {
    const result =
      await this.detect(input);

    return result.prediction;
  }
}