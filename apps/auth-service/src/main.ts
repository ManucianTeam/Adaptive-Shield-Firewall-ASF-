// apps/auth-service/src/main.ts

import {
  Logger,
  ValidationPipe,
} from '@nestjs/common';

import { NestFactory } from '@nestjs/core';

import {
  ConfigService,
} from '@nestjs/config';

import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';

import { AppModule } from './app.module';

// ============================================================================
// Bootstrap Application
// ============================================================================

async function bootstrap(): Promise<void> {
  // ==========================================================================
  // Create Nest Application
  // ==========================================================================

  const app = await NestFactory.create(
    AppModule,
    {
      cors: false,
    },
  );

  // ==========================================================================
  // Logger
  // ==========================================================================

  const logger = new Logger(
    'ASF-Bootstrap',
  );

  // ==========================================================================
  // Configuration Service
  // ==========================================================================

  const configService =
    app.get(ConfigService);

  // ==========================================================================
  // Security Middleware
  // ==========================================================================

  app.use(
    helmet({
      crossOriginResourcePolicy: false,
    }),
  );

  // ==========================================================================
  // Compression Middleware
  // ==========================================================================

  app.use(
    compression(),
  );

  // ==========================================================================
  // Cookie Parser
  // ==========================================================================

  app.use(
    cookieParser(),
  );

  // ==========================================================================
  // Global Prefix
  // ==========================================================================

  app.setGlobalPrefix('api');

  // ==========================================================================
  // Validation Pipe
  // ==========================================================================

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,

      forbidNonWhitelisted: true,

      transform: true,

      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // ==========================================================================
  // CORS Configuration
  // ==========================================================================

  app.enableCors({
    origin:
      configService.get<string>(
        'security.corsOrigin',
      ) || '*',

    credentials: true,

    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS',
    ],

    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-Device-Fingerprint',
    ],
  });

  // ==========================================================================
  // Graceful Shutdown Hooks
  // ==========================================================================

  app.enableShutdownHooks();

  // ==========================================================================
  // Application Port
  // ==========================================================================

  const port =
    configService.get<number>('PORT') ||
    3000;

  // ==========================================================================
  // Start Application
  // ==========================================================================

  await app.listen(port);

  // ==========================================================================
  // Startup Logs
  // ==========================================================================

  logger.log(
    `Adaptive Shield Firewall (ASF) running on port ${port}`,
  );

  logger.log(
    `Environment: ${
      process.env.NODE_ENV ||
      'development'
    }`,
  );

  logger.log(
    `API Endpoint: http://localhost:${port}/api`,
  );
}

// ============================================================================
// Bootstrap Execution
// ============================================================================

bootstrap();
