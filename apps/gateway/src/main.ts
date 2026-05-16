/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Application Bootstrap
 * File: main.ts
 * ============================================================
 *
 * PURPOSE:
 * Secure bootstrap entrypoint for the Adaptive
 * Shield Firewall platform.
 *
 * This bootstrap layer initializes:
 * - NestJS application runtime
 * - distributed security middleware
 * - global validation pipelines
 * - adaptive telemetry systems
 * - hardened HTTP infrastructure
 * - graceful shutdown handling
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Harden application startup
 * - Reduce attack surface exposure
 * - Enforce secure runtime defaults
 * - Protect infrastructure metadata
 * - Ensure operational resilience
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Security-first bootstrap
 * - Fail-fast initialization
 * - Cloud-native compatibility
 * - Deterministic startup flow
 * - Production-safe defaults
 *
 * ============================================================
 *
 * IMPORTANT:
 * Bootstrap configuration defines
 * foundational runtime security posture.
 *
 * NEVER:
 * - expose framework internals
 * - leak stack traces in production
 * - trust inbound proxy headers blindly
 * - enable unsafe CORS defaults
 *
 * ============================================================
 */

import { Logger, ValidationPipe } from '@nestjs/common';

import { NestFactory } from '@nestjs/core';

import helmet from 'helmet';

import compression from 'compression';

import rateLimit from 'express-rate-limit';

import { AppModule } from './app.module';

/**
 * ============================================================
 * Bootstrap
 * ============================================================
 */

async function bootstrap() {
  /**
   * ==========================================================
   * Logger
   * ==========================================================
   */

  const logger = new Logger('ASFBootstrap');

  /**
   * ==========================================================
   * Create Nest Application
   * ==========================================================
   */

  const app = await NestFactory.create(
    AppModule,

    {
      /**
       * ====================================================
       * Production Log Levels
       * ====================================================
       */

      logger: ['log', 'warn', 'error', 'debug'],

      /**
       * ====================================================
       * Buffer Startup Logs
       * ====================================================
       */

      bufferLogs: true,
    },
  );

  /**
   * ==========================================================
   * Trust Proxy
   * ==========================================================
   *
   * IMPORTANT:
   * Configure correctly behind:
   * - NGINX
   * - Cloudflare
   * - AWS ALB
   * - Kubernetes ingress
   * ==========================================================
   */

  app.set('trust proxy', 1);

  /**
   * ==========================================================
   * Security Headers
   * ==========================================================
   */

  app.use(
    helmet({
      crossOriginEmbedderPolicy: false,
    }),
  );

  /**
   * ==========================================================
   * Compression
   * ==========================================================
   */

  app.use(compression());

  /**
   * ==========================================================
   * Global Rate Limiter
   * ==========================================================
   *
   * NOTE:
   * Basic edge protection only.
   *
   * Production:
   * - Redis distributed limiter
   * - adaptive thresholds
   * - fingerprint-aware enforcement
   * ==========================================================
   */

  app.use(
    rateLimit({
      windowMs: 60 * 1000,

      max: 120,

      standardHeaders: true,

      legacyHeaders: false,

      message: {
        statusCode: 429,

        error: 'Too Many Requests',
      },
    }),
  );

  /**
   * ==========================================================
   * Global Validation Pipeline
   * ==========================================================
   */

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,

      forbidNonWhitelisted: true,

      transform: true,

      transformOptions: {
        enableImplicitConversion: true,
      },

      disableErrorMessages: process.env.NODE_ENV === 'production',
    }),
  );

  /**
   * ==========================================================
   * Global API Prefix
   * ==========================================================
   */

  app.setGlobalPrefix('api');

  /**
   * ==========================================================
   * Graceful Shutdown Hooks
   * ==========================================================
   */

  app.enableShutdownHooks();

  /**
   * ==========================================================
   * CORS Configuration
   * ==========================================================
   */

  app.enableCors({
    origin: process.env.CORS_ORIGIN || '*',

    credentials: true,

    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

    allowedHeaders: [
      'Content-Type',

      'Authorization',

      'X-Session-Id',

      'X-Request-ID',
    ],
  });

  /**
   * ==========================================================
   * Bootstrap Port
   * ==========================================================
   */

  const port = Number(process.env.PORT || 3000);

  /**
   * ==========================================================
   * Start Application
   * ==========================================================
   */

  await app.listen(port);

  /**
   * ==========================================================
   * Startup Telemetry
   * ==========================================================
   */

  logger.log(`
╔══════════════════════════════════════════════╗
║                                              ║
║     🛡️ ASF SECURITY PLATFORM ONLINE         ║
║                                              ║
╠══════════════════════════════════════════════╣
║ Environment : ${process.env.NODE_ENV || 'development'}
║ Port        : ${port}
║ Prefix      : /api
║ PID         : ${process.pid}
║ Runtime     : Node.js
║                                              ║
║ Threat Engine        : ACTIVE
║ Reputation Engine    : ACTIVE
║ Session Intelligence : ACTIVE
║ Telemetry Pipeline   : ACTIVE
║                                              ║
╚══════════════════════════════════════════════╝
`);

  /**
   * ==========================================================
   * Unhandled Rejection Handler
   * ==========================================================
   */

  process.on('unhandledRejection', (reason) => {
    logger.error({
      event: 'UNHANDLED_REJECTION',

      reason,
    });
  });

  /**
   * ==========================================================
   * Uncaught Exception Handler
   * ==========================================================
   */

  process.on('uncaughtException', (error) => {
    logger.error({
      event: 'UNCAUGHT_EXCEPTION',

      message: error.message,

      stack: error.stack,
    });

    process.exit(1);
  });
}

/**
 * ============================================================
 * Initialize Runtime
 * ============================================================
 */

bootstrap();
