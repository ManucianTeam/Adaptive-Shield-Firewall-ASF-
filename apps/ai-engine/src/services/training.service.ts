// apps/gateway/src/ai-engine/training.service.ts

import { Injectable, Logger } from '@nestjs/common';

import {
  PredictionInput,
} from './interfaces/prediction.interface';

@Injectable()
export class TrainingService {
  private readonly logger = new Logger(
    TrainingService.name,
  );

  // =========================
  // IN-MEMORY DATASET
  // =========================

  private readonly dataset: PredictionInput[] =
    [];

  // =========================
  // SAVE TRAINING DATA
  // =========================

  async train(
    input: PredictionInput,
  ): Promise<void> {
    this.dataset.push(input);

    this.logger.log(
      `[TRAINING] saved sample from ${input.ip}`,
    );
  }

  // =========================
  // BULK TRAINING
  // =========================

  async bulkTrain(
    inputs: PredictionInput[],
  ): Promise<void> {
    this.dataset.push(...inputs);

    this.logger.log(
      `[TRAINING] bulk inserted ${inputs.length} samples`,
    );
  }

  // =========================
  // GET DATASET
  // =========================

  async getDataset(): Promise<PredictionInput[]> {
    return this.dataset;
  }

  // =========================
  // DATASET SIZE
  // =========================

  async size(): Promise<number> {
    return this.dataset.length;
  }

  // =========================
  // CLEAR DATASET
  // =========================

  async clear(): Promise<void> {
    this.dataset.length = 0;

    this.logger.warn(
      `[TRAINING] dataset cleared`,
    );
  }

  // =========================
  // SIMPLE LABELING
  // =========================

  async autoLabel(
    input: PredictionInput,
  ): Promise<
    'safe' | 'suspicious' | 'malicious'
  > {
    let score = 0;

    if ((input.requestCount || 0) > 500) {
      score += 20;
    }

    if ((input.failedRequests || 0) > 50) {
      score += 20;
    }

    if ((input.anomalyCount || 0) > 10) {
      score += 30;
    }

    if (input.isBot) {
      score += 40;
    }

    if (input.isTor) {
      score += 30;
    }

    if (input.raceConditionDetected) {
      score += 30;
    }

    if (score >= 80) {
      return 'malicious';
    }

    if (score >= 40) {
      return 'suspicious';
    }

    return 'safe';
  }

  // =========================
  // SIMPLE FEATURE EXTRACTOR
  // =========================

  async extractFeatures(
    input: PredictionInput,
  ): Promise<number[]> {
    return [
      input.requestCount || 0,
      input.failedRequests || 0,
      input.anomalyCount || 0,
      input.blockedCount || 0,
      input.suspiciousScore || 0,

      input.isVpn ? 1 : 0,
      input.isTor ? 1 : 0,
      input.isProxy ? 1 : 0,
      input.isBot ? 1 : 0,

      input.raceConditionDetected ? 1 : 0,
    ];
  }
}