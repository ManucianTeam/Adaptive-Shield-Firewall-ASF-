// apps/auth-service/src/auth/auth.module.ts

import {
  MiddlewareConsumer,
  Module,
  NestModule,
  RequestMethod,
} from '@nestjs/common';

import { JwtModule } from '@nestjs/jwt';

import { PassportModule } from '@nestjs/passport';

import { ConfigModule } from '@nestjs/config';

import { EventEmitterModule } from '@nestjs/event-emitter';

/**
 * ============================================================================
 * Internal Modules
 * ============================================================================
 */

import { AuthController } from './controllers/auth.controller';

import { AuthService } from './services/auth.service';

import { TokenService } from './services/token.service';

import { SessionService } from './services/session.service';

import { PasswordService } from './services/password.service';

/**
 * ============================================================================
 * Security Strategies
 * ============================================================================
 */

import { JwtStrategy } from './strategies/jwt.strategy';

import { RefreshStrategy } from './strategies/refresh.strategy';

/**
 * ============================================================================
 * Security Guards
 * ============================================================================
 */

import { JwtAuthGuard } from './guards/jwt-auth.guard';

import { RolesGuard } from './guards/roles.guard';

import { SuspiciousGuard } from './guards/suspicious.guard';

/**
 * ============================================================================
 * Middleware
 * ============================================================================
 */

import { FingerprintMiddleware } from './middleware/fingerprint.middleware';

import { IpReputationMiddleware } from './middleware/ip-reputation.middleware';

import { RequestTrackingMiddleware } from './middleware/request-tracking.middleware';

/**
 * ============================================================================
 * External Modules
 * ============================================================================
 */

import { UsersModule } from '../users/users.module';

import { RedisModule } from '../redis/redis.module';

import { AiSecurityModule } from '../ai-security/ai-security.module';

/**
 * ============================================================================
 * ASF Authentication Module
 * ============================================================================
 *
 * Enterprise-grade authentication orchestration module engineered for
 * distributed Zero Trust infrastructures and adaptive identity systems.
 *
 * Core Responsibilities:
 *
 *  - distributed authentication orchestration
 *  - JWT lifecycle management
 *  - session hardening
 *  - adaptive access validation
 *  - AI-assisted threat mitigation
 *  - distributed identity propagation
 *
 * Security Architecture:
 *
 *  - stateless JWT authentication
 *  - Redis-backed session persistence
 *  - adaptive threat analysis
 *  - middleware-driven telemetry
 *  - replay-resistant refresh lifecycle
 *  - fingerprint-aware access control
 *
 * Integrated Domains:
 *
 *  - AuthController
 *  - AuthService
 *  - TokenService
 *  - SessionService
 *  - PasswordService
 *  - JwtStrategy
 *  - RefreshStrategy
 *  - AI Security Pipeline
 *
 * Designed For:
 *
 *  - distributed microservices
 *  - enterprise IAM infrastructures
 *  - API gateways
 *  - adaptive access-control systems
 *  - AI-driven authentication fabrics
 *
 * ============================================================================
 */

@Module({
  /**
   * --------------------------------------------------------------------------
   * Module Imports
   * --------------------------------------------------------------------------
   */

  imports: [
    /**
     * ------------------------------------------------------------------------
     * Environment Configuration
     * ------------------------------------------------------------------------
     */

    ConfigModule,

    /**
     * ------------------------------------------------------------------------
     * Event Infrastructure
     * ------------------------------------------------------------------------
     */

    EventEmitterModule.forRoot(),

    /**
     * ------------------------------------------------------------------------
     * Passport Authentication Framework
     * ------------------------------------------------------------------------
     */

    PassportModule.register({
      defaultStrategy:
        'jwt',

      session:
        false,
    }),

    /**
     * ------------------------------------------------------------------------
     * JWT Infrastructure
     * ------------------------------------------------------------------------
     */

    JwtModule.register({
      secret:
        process.env.JWT_ACCESS_SECRET,

      signOptions: {
        expiresIn:
          '15m',
      },
    }),

    /**
     * ------------------------------------------------------------------------
     * Distributed Infrastructure Modules
     * ------------------------------------------------------------------------
     */

    UsersModule,

    RedisModule,

    AiSecurityModule,
  ],

  /**
   * --------------------------------------------------------------------------
   * HTTP Controllers
   * --------------------------------------------------------------------------
   */

  controllers: [
    AuthController,
  ],

  /**
   * --------------------------------------------------------------------------
   * Dependency Injection Providers
   * --------------------------------------------------------------------------
   */

  providers: [
    /**
     * ------------------------------------------------------------------------
     * Core Services
     * ------------------------------------------------------------------------
     */

    AuthService,

    TokenService,

    SessionService,

    PasswordService,

    /**
     * ------------------------------------------------------------------------
     * Security Strategies
     * ------------------------------------------------------------------------
     */

    JwtStrategy,

    RefreshStrategy,

    /**
     * ------------------------------------------------------------------------
     * Authorization Guards
     * ------------------------------------------------------------------------
     */

    JwtAuthGuard,

    RolesGuard,

    SuspiciousGuard,
  ],

  /**
   * --------------------------------------------------------------------------
   * Exported Security Infrastructure
   * --------------------------------------------------------------------------
   */

  exports: [
    AuthService,

    TokenService,

    SessionService,

    PasswordService,

    JwtModule,

    PassportModule,
  ],
})

/**
 * ============================================================================
 * Middleware Orchestration Layer
 * ============================================================================
 */

export class AuthModule
  implements NestModule
{
  configure(
    consumer: MiddlewareConsumer,
  ): void {
    /**
     * ------------------------------------------------------------------------
     * Adaptive Security Middleware Pipeline
     * ------------------------------------------------------------------------
     */

    consumer
      .apply(
        /**
         * --------------------------------------------------------------------
         * Request Correlation & Traceability
         * --------------------------------------------------------------------
         */

        RequestTrackingMiddleware,

        /**
         * --------------------------------------------------------------------
         * Device Fingerprinting
         * --------------------------------------------------------------------
         */

        FingerprintMiddleware,

        /**
         * --------------------------------------------------------------------
         * IP Reputation & Threat Telemetry
         * --------------------------------------------------------------------
         */

        IpReputationMiddleware,
      )

      /**
       * ----------------------------------------------------------------------
       * Protected Authentication Surface
       * ----------------------------------------------------------------------
       */

      .forRoutes({
        path:
          'auth/*',

        method:
          RequestMethod.ALL,
      });
  }
}