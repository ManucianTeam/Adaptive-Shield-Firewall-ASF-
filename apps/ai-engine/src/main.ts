// apps/ai-engine/src/main.ts

import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';

import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(
    AppModule,
  );

  // CORS
  app.enableCors();

  // Validation
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
  );

  // Prefix
  app.setGlobalPrefix('api');

  // Listen
  await app.listen(4000);

  console.log(
    '🚀 AI Engine Running on http://localhost:4000/api',
  );
}

bootstrap();