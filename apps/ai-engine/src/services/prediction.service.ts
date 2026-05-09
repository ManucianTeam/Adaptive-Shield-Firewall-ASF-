// apps/gateway/src/ai-engine/prediction.service.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  PredictionInput,
  PredictionResult,
} from './interfaces/prediction.interface';

import {
  DetectionService,
} from './detection.service';

@Injectable()
export class PredictionService {
  private readonly logger = new Logger(
    PredictionService.name,
  );

  constructor(
    private readonly detectionService: DetectionService,
  ) {}

  // =========================
  // MAIN PREDICTION
  // =========================

  async predict(
    input: PredictionInput,
  ): Promise<PredictionResult> {
    const result =
      await this.detectionService.detect(
        input,
      );

    // =========================
    // EXTRA LOGGING
    // =========================

    this.logger.warn(
      `[PREDICTION] ${input.ip} => ${result.prediction}`,
    );

    return result;
  }

  // =========================
  // THREAT CHECK
  // =========================

  async isThreat(
    input: PredictionInput,
  ): Promise<boolean> {
    const result =
      await this.predict(input);

    return (
      result.prediction === 'malicious' ||
      result.prediction === 'critical'
    );
  }

  // =========================
  // SAFE CHECK
  // =========================

  async isSafe(
    input: PredictionInput,
  ): Promise<boolean> {
    const result =
      await this.predict(input);

    return result.prediction === 'safe';
  }

  // =========================
  // BLOCK CHECK
  // =========================

  async shouldBlock(
    input: PredictionInput,
  ): Promise<boolean> {
    const result =
      await this.predict(input);

    return result.shouldBlock;
  }

  // =========================
  // MONITOR CHECK
  // =========================

  async shouldMonitor(
    input: PredictionInput,
  ): Promise<boolean> {
    const result =
      await this.predict(input);

    return result.shouldMonitor;
  }

  // =========================
  // GET CONFIDENCE
  // =========================

  async getConfidence(
    input: PredictionInput,
  ): Promise<number> {
    const result =
      await this.predict(input);

    return result.confidence;
  }

  // =========================
  // GET RISK SCORE
  // =========================

  async getRiskScore(
    input: PredictionInput,
  ): Promise<number> {
    const result =
      await this.predict(input);

    return result.riskScore;
  }
}