// apps/ai-engine/src/controllers/predictions.controller.ts

import {
  Body,
  Controller,
  Post,
} from '@nestjs/common';

import {
  PredictionInput,
} from '../ai-engine/interfaces/prediction.interface';

import {
  PredictionService,
} from '../ai-engine/prediction.service';

@Controller('prediction')
export class PredictionsController {
  constructor(
    private readonly predictionService: PredictionService,
  ) {}

  // =========================
  // FULL PREDICTION
  // =========================

  @Post()
  async predict(
    @Body() body: PredictionInput,
  ) {
    return this.predictionService.predict(
      body,
    );
  }

  // =========================
  // THREAT CHECK
  // =========================

  @Post('threat')
  async isThreat(
    @Body() body: PredictionInput,
  ) {
    const threat =
      await this.predictionService.isThreat(
        body,
      );

    return {
      threat,
    };
  }

  // =========================
  // SAFE CHECK
  // =========================

  @Post('safe')
  async isSafe(
    @Body() body: PredictionInput,
  ) {
    const safe =
      await this.predictionService.isSafe(
        body,
      );

    return {
      safe,
    };
  }

  // =========================
  // BLOCK CHECK
  // =========================

  @Post('block')
  async shouldBlock(
    @Body() body: PredictionInput,
  ) {
    const blocked =
      await this.predictionService.shouldBlock(
        body,
      );

    return {
      blocked,
    };
  }

  // =========================
  // MONITOR CHECK
  // =========================

  @Post('monitor')
  async shouldMonitor(
    @Body() body: PredictionInput,
  ) {
    const monitor =
      await this.predictionService.shouldMonitor(
        body,
      );

    return {
      monitor,
    };
  }

  // =========================
  // GET CONFIDENCE
  // =========================

  @Post('confidence')
  async confidence(
    @Body() body: PredictionInput,
  ) {
    const confidence =
      await this.predictionService.getConfidence(
        body,
      );

    return {
      confidence,
    };
  }

  // =========================
  // GET RISK SCORE
  // =========================

  @Post('risk-score')
  async riskScore(
    @Body() body: PredictionInput,
  ) {
    const riskScore =
      await this.predictionService.getRiskScore(
        body,
      );

    return {
      riskScore,
    };
  }
}