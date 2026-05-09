// apps/ai-engine/src/controllers/ai.controller.ts

import {
  Body,
  Controller,
  Get,
  Post,
} from '@nestjs/common';

import {
  PredictionInput,
} from '../ai-engine/interfaces/prediction.interface';

import {
  AIEngineService,
} from '../ai-engine/ai-engine.service';

import {
  DetectionService,
} from '../ai-engine/detection.service';

import {
  PredictionService,
} from '../ai-engine/prediction.service';

import {
  TrainingService,
} from '../ai-engine/training.service';

@Controller('ai')
export class AIController {
  constructor(
    private readonly aiEngineService: AIEngineService,

    private readonly detectionService: DetectionService,

    private readonly predictionService: PredictionService,

    private readonly trainingService: TrainingService,
  ) {}

  // =========================
  // ANALYZE
  // =========================

  @Post('analyze')
  async analyze(
    @Body() body: PredictionInput,
  ) {
    return this.aiEngineService.analyze(
      body,
    );
  }

  // =========================
  // DETECT
  // =========================

  @Post('detect')
  async detect(
    @Body() body: PredictionInput,
  ) {
    return this.detectionService.detect(
      body,
    );
  }

  // =========================
  // PREDICT
  // =========================

  @Post('predict')
  async predict(
    @Body() body: PredictionInput,
  ) {
    return this.predictionService.predict(
      body,
    );
  }

  // =========================
  // TRAIN
  // =========================

  @Post('train')
  async train(
    @Body() body: PredictionInput,
  ) {
    await this.trainingService.train(
      body,
    );

    return {
      success: true,
      message:
        'Training sample added successfully',
    };
  }

  // =========================
  // DATASET
  // =========================

  @Get('dataset')
  async dataset() {
    return this.trainingService.getDataset();
  }

  // =========================
  // DATASET SIZE
  // =========================

  @Get('dataset/size')
  async datasetSize() {
    const size =
      await this.trainingService.size();

    return {
      size,
    };
  }

  // =========================
  // CLEAR DATASET
  // =========================

  @Post('dataset/clear')
  async clearDataset() {
    await this.trainingService.clear();

    return {
      success: true,
      message: 'Dataset cleared',
    };
  }
}