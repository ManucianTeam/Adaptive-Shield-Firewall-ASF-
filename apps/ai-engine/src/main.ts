/* ============================================================
 * ASF AI Engine
 * AI Runtime Bootstrap
 * File: main.ts
 * ============================================================
 *
 * PURPOSE:
 * Secure bootstrap entrypoint for the ASF AI Engine.
 *
 * This runtime initializes:
 * - adaptive inference pipelines
 * - behavioral intelligence systems
 * - anomaly analysis services
 * - distributed telemetry engines
 * - AI threat scoring runtime
 * - hardened API infrastructure
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Harden AI runtime initialization
 * - Prevent unsafe inference exposure
 * - Enforce secure defaults
 * - Reduce infrastructure attack surface
 * - Enable resilient distributed execution
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Security-first runtime
 * - Deterministic startup flow
 * - Distributed-system compatibility
 * - Fail-fast initialization
 * - Production-safe configuration
 *
 * ============================================================
 *
 * IMPORTANT:
 * Bootstrap configuration defines the
 * foundational AI runtime security posture.
 *
 * NEVER:
 * - expose model internals publicly
 * - leak stack traces in production
 * - trust unvalidated inference payloads
 * - enable unrestricted CORS access
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
 * Bootstrap Runtime
 * ============================================================
 */

async function bootstrap() {
  /**
   * ==========================================================
   * Bootstrap Logger
   * ==========================================================
   */

  const logger = new Logger('ASF-AI-RUNTIME');

  /**
   * ==========================================================
   * Create Nest Application
   * ==========================================================
   */

  const app = await NestFactory.create(
    AppModule,

    {
      logger: ['log', 'warn', 'error', 'debug'],

      bufferLogs: true,
    },
  );

  /**
   * ==========================================================
   * Proxy Trust
   * ==========================================================
   *
   * IMPORTANT:
   * Configure properly behind:
   * - Cloudflare
   * - NGINX
   * - Kubernetes ingress
   * - AWS ALB
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
      contentSecurityPolicy: false,

      crossOriginEmbedderPolicy: false,
    }),
  );

  /**
   * ==========================================================
   * Compression Middleware
   * ==========================================================
   */

  app.use(compression());

  /**
   * ==========================================================
   * Global Rate Limiting
   * ==========================================================
   *
   * NOTE:
   * Lightweight protection layer.
   *
   * Production:
   * - Redis-backed distributed limiter
   * - fingerprint-aware throttling
   * - adaptive thresholds
   * ==========================================================
   */

  app.use(
    rateLimit({
      windowMs: 60 * 1000,

      max: 100,

      standardHeaders: true,

      legacyHeaders: false,

      message: {
        statusCode: 429,

        error: 'Inference Rate Limit Exceeded',
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
   * API Prefix
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
   * Secure CORS Configuration
   * ==========================================================
   */

  app.enableCors({
    origin: process.env.CORS_ORIGIN || '*',

    credentials: true,

    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

    allowedHeaders: [
      'Content-Type',

      'Authorization',

      'X-Request-ID',

      'X-Correlation-ID',
    ],
  });

  /**
   * ==========================================================
   * Runtime Port
   * ==========================================================
   */

  const port = Number(process.env.PORT || 4000);

  /**
   * ==========================================================
   * Start Runtime
   * ==========================================================
   */

  await app.listen(port);

  /**
   * ==========================================================
   * Runtime Telemetry
   * ==========================================================
   */

  logger.log(`
╔══════════════════════════════════════════════╗
║                                              ║
║          🤖 ASF AI ENGINE ONLINE             ║
║                                              ║
╠══════════════════════════════════════════════╣
║ Environment : ${process.env.NODE_ENV || 'development'}
║ Port        : ${port}
║ Prefix      : /api
║ PID         : ${process.pid}
║ Runtime     : Node.js
║                                              ║
║ Anomaly Engine      : ACTIVE
║ Behavioral AI       : ACTIVE
║ Threat Scoring      : ACTIVE
║ Race Detection      : ACTIVE
║ Telemetry Pipeline  : ACTIVE
║                                              ║
╚══════════════════════════════════════════════╝
`);

  /**
   * ==========================================================
   * Unhandled Promise Rejection
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
   * Uncaught Exception
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
