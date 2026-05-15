/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Root Application Module
 * File: app.module.ts
 * ============================================================
 *
 * PURPOSE:
 * Central bootstrap module for the Adaptive Shield
 * Firewall security platform.
 *
 * This module orchestrates:
 * - distributed threat intelligence
 * - behavioral anomaly analysis
 * - adaptive session protection
 * - reputation intelligence
 * - Redis-backed distributed services
 * - middleware + interceptors
 * - security telemetry pipelines
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Centralize security orchestration
 * - Enforce layered defense architecture
 * - Enable zero-trust request evaluation
 * - Coordinate distributed mitigation systems
 * - Harden application entry points
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Modular architecture
 * - Stateless service orchestration
 * - Distributed-ready deployment
 * - Security-first defaults
 * - Future AI extensibility
 *
 * ============================================================
 *
 * IMPORTANT:
 * AppModule is the composition root only.
 *
 * NEVER:
 * - place business logic here
 * - implement heavy runtime operations
 * - expose sensitive internals
 * - bypass security middleware
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

import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';

/**
 * ============================================================
 * Controllers
 * ============================================================
 */

import { AppController } from './app.controller';

/**
 * ============================================================
 * Services
 * ============================================================
 */

import { ThreatService } from './services/threat.service';

import { AnomalyService } from './services/anomaly.service';

import { ReputationService } from './services/reputation.service';

import { SessionService } from './services/session.service';

import { ThreatCorrelationService } from './services/threat-correlation.service';

import { RedisLockService } from './services/redis-lock.service';

/**
 * ============================================================
 * Guards
 * ============================================================
 */

import { ThreatGuard } from './guards/threat.guard';

/**
 * ============================================================
 * Interceptors
 * ============================================================
 */

import { TelemetryInterceptor } from './interceptors/telemetry.interceptor';

/**
 * ============================================================
 * Middleware
 * ============================================================
 */

import { FingerprintMiddleware } from './middleware/fingerprint.middleware';

import { RequestContextMiddleware } from './middleware/request-context.middleware';

/**
 * ============================================================
 * Modules
 * ============================================================
 */

@Module({
  /**
   * ==========================================================
   * Global Imports
   * ==========================================================
   */

  imports: [
    /**
     * ========================================================
     * Environment Configuration
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
     * Core Security Services
     * ========================================================
     */

    ThreatService,

    AnomalyService,

    ReputationService,

    SessionService,

    ThreatCorrelationService,

    RedisLockService,

    /**
     * ========================================================
     * Global Threat Guard
     * ========================================================
     */

    {
      provide: APP_GUARD,

      useClass: ThreatGuard,
    },

    /**
     * ========================================================
     * Global Telemetry Interceptor
     * ========================================================
     */

    {
      provide: APP_INTERCEPTOR,

      useClass: TelemetryInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  /**
   * ==========================================================
   * Configure Middleware Pipeline
   * ==========================================================
   */

  configure(consumer: MiddlewareConsumer): void {
    /**
     * ========================================================
     * Request Context Middleware
     * ========================================================
     */

    consumer.apply(RequestContextMiddleware).forRoutes({
      path: '*',

      method: RequestMethod.ALL,
    });

    /**
     * ========================================================
     * Fingerprint Middleware
     * ========================================================
     */

    consumer.apply(FingerprintMiddleware).forRoutes({
      path: '*',

      method: RequestMethod.ALL,
    });
  }
}
