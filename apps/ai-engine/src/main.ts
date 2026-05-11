import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  await app.listen(3001); // AI ENGINE port
  console.log('AI Engine running on http://localhost:3001');
}

bootstrap();