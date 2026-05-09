// apps/gateway/src/app.module.ts

import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { MongooseModule } from '@nestjs/mongoose';

// =========================
// MODELS
// =========================

import {
  Anomaly,
  AnomalySchema,
} from './database/models/anomaly.model';

import {
  Behavior,
  BehaviorSchema,
} from './database/models/behavior.model';

import {
  Race,
  RaceSchema,
} from './database/models/race.model';

import {
  Scoring,
  ScoringSchema,
} from './database/models/scoring.model';

// =========================
// AI ENGINES
// =========================

import { AIScoreEngine } from './ai-engine/ai-score.engine';
import { ConfidenceEngine } from './ai-engine/confidence.engine';
import { RiskScoreEngine } from './ai-engine/risk-score.engine';

// =========================
// SERVICES
// =========================

import { AIEngineService } from './ai-engine/ai-engine.service';
import { DetectionService } from './ai-engine/detection.service';
import { PredictionService } from './ai-engine/prediction.service';
import { TrainingService } from './ai-engine/training.service';

@Module({
  imports: [
    // =========================
    // ENV
    // =========================

    ConfigModule.forRoot({
      isGlobal: true,
    }),

    // =========================
    // DATABASE
    // =========================

    MongooseModule.forRoot(
      process.env.MONGO_URI ||
        'mongodb://localhost:27017/security-ai',
    ),

    // =========================
    // SCHEMAS
    // =========================

    MongooseModule.forFeature([
      {
        name: Anomaly.name,
        schema: AnomalySchema,
      },
      {
        name: Behavior.name,
        schema: BehaviorSchema,
      },
      {
        name: Race.name,
        schema: RaceSchema,
      },
      {
        name: Scoring.name,
        schema: ScoringSchema,
      },
    ]),
  ],

  // =========================
  // PROVIDERS
  // =========================

  providers: [
    // Engines
    AIScoreEngine,
    ConfidenceEngine,
    RiskScoreEngine,

    // Services
    AIEngineService,
    DetectionService,
    PredictionService,
    TrainingService,
  ],

  exports: [
    AIEngineService,
    DetectionService,
    PredictionService,
    TrainingService,
  ],
})
export class AppModule {}