/* ============================================================
 * ASF AI Engine
 * Root AI Runtime Module
 * File: app.module.ts
 * ============================================================
 *
 * PURPOSE:
 * Central orchestration module for the ASF AI Engine.
 *
 * This module coordinates:
 * - anomaly intelligence
 * - behavioral analysis
 * - adaptive scoring systems
 * - race-condition intelligence
 * - distributed inference pipelines
 * - telemetry aggregation
 * - AI-driven threat correlation
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Centralize AI orchestration
 * - Harden inference pipelines
 * - Prevent inconsistent scoring
 * - Support zero-trust analysis
 * - Enable distributed intelligence
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Modular architecture
 * - Stateless AI services
 * - Distributed compatibility
 * - Explainable intelligence
 * - Future ML extensibility
 *
 * ============================================================
 *
 * IMPORTANT:
 * This module acts only as the AI composition root.
 *
 * NEVER:
 * - implement heavy logic here
 * - expose internal AI heuristics
 * - bypass telemetry pipelines
 * - trust unvalidated inference data
 *
 * ============================================================
 */

import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';

import { ConfigModule } from '@nestjs/config';

import { APP_INTERCEPTOR } from '@nestjs/core';

/**
 * ============================================================
 * Controllers
 * ============================================================
 */

import { AppController } from './app.controller';

/**
 * ============================================================
 * AI Services
 * ============================================================
 */

import { AnomalyEngineService } from './services/anomaly-engine.service';

import { BehaviorAnalysisService } from './services/behavior-analysis.service';

import { AdaptiveScoringService } from './services/adaptive-scoring.service';

import { RaceDetectionService } from './services/race-detection.service';

import { ThreatCorrelationService } from './services/threat-correlation.service';

/**
 * ============================================================
 * Middleware
 * ============================================================
 */

import { TelemetryMiddleware } from './middleware/telemetry.middleware';

import { InferenceContextMiddleware } from './middleware/inference-context.middleware';

/**
 * ============================================================
 * Interceptors
 * ============================================================
 */

import { AIInferenceInterceptor } from './interceptors/ai-inference.interceptor';

/**
 * ============================================================
 * Runtime Module
 * ============================================================
 */

@Module({
  /**
   * ==========================================================
   * Imports
   * ==========================================================
   */

  imports: [
    /**
     * ========================================================
     * Global Config
     * ========================================================
     */

    ConfigModule.forRoot({
      isGlobal: true,

      cache: true,

      expandVariables: true,
    }),
  ],

  /**
   * ==========================================================
   * Controllers
   * ==========================================================
   */

  controllers: [AppController],

  /**
   * ==========================================================
   * Providers
   * ==========================================================
   */

  providers: [
    /**
     * ========================================================
     * AI Core Services
     * ========================================================
     */

    AnomalyEngineService,

    BehaviorAnalysisService,

    AdaptiveScoringService,

    RaceDetectionService,

    ThreatCorrelationService,

    /**
     * ========================================================
     * Global AI Interceptor
     * ========================================================
     */

    {
      provide: APP_INTERCEPTOR,

      useClass: AIInferenceInterceptor,
    },
  ],

  /**
   * ==========================================================
   * Exports
   * ==========================================================
   */

  exports: [
    AnomalyEngineService,

    BehaviorAnalysisService,

    AdaptiveScoringService,

    RaceDetectionService,

    ThreatCorrelationService,
  ],
})
export class AppModule implements NestModule {
  /**
   * ==========================================================
   * Middleware Pipeline
   * ==========================================================
   */

  configure(consumer: MiddlewareConsumer): void {
    /**
     * ========================================================
     * Inference Context Middleware
     * ========================================================
     */

    consumer.apply(InferenceContextMiddleware).forRoutes({
      path: '*',

      method: RequestMethod.ALL,
    });

    /**
     * ========================================================
     * Telemetry Middleware
     * ========================================================
     */

    consumer.apply(TelemetryMiddleware).forRoutes({
      path: '*',

      method: RequestMethod.ALL,
    });
  }
}
