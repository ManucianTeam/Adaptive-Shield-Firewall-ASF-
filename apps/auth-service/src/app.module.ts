// apps/auth-service/src/app.module.ts

import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

// ============================================================================
// Configuration
// ============================================================================

import databaseConfig from './config/database.config';
import jwtConfig from './config/jwt.config';
import redisConfig from './config/redis.config';
import securityConfig from './config/security.config';

// ============================================================================
// Infrastructure Modules
// ============================================================================

import { DatabaseModule } from './database/database.module';
import { RedisModule } from './redis/redis.module';

// ============================================================================
// Feature Modules
// ============================================================================

import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { AiSecurityModule } from './ai-security/ai-security.module';

// ============================================================================
// Root Application Module
// ============================================================================

@Module({
  imports: [
    // ==========================================================================
    // Global Configuration
    // ==========================================================================

    ConfigModule.forRoot({
      isGlobal: true,

      envFilePath: '.env',

      load: [
        databaseConfig,
        jwtConfig,
        redisConfig,
        securityConfig,
      ],
    }),

    // ==========================================================================
    // Core Infrastructure
    // ==========================================================================

    DatabaseModule,

    RedisModule,

    // ==========================================================================
    // Feature Domains
    // ==========================================================================

    AuthModule,

    UsersModule,

    AiSecurityModule,
  ],
})
export class AppModule {}
