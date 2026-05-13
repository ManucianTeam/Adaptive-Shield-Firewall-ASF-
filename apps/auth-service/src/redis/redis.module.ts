// apps/auth-service/src/redis/redis.module.ts

import {
  Global,
  Logger,
  Module,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';

import {
  ConfigModule,
  ConfigService,
} from '@nestjs/config';

import Redis from 'ioredis';

/**
 * ============================================================================
 * Internal Services
 * ============================================================================
 */

import { RedisService } from './redis.service';

import { DistributedLockService } from './distributed-lock.service';

/**
 * ============================================================================
 * ASF Redis Infrastructure Module
 * ============================================================================
 *
 * Enterprise-grade Redis infrastructure module engineered for distributed
 * authentication systems, adaptive Zero Trust environments, and
 * high-concurrency microservice architectures.
 *
 * Core Responsibilities:
 *
 *  - centralized Redis orchestration
 *  - distributed cache infrastructure
 *  - session persistence coordination
 *  - pub/sub communication enablement
 *  - distributed locking infrastructure
 *  - high-availability connection management
 *
 * Security Architecture:
 *
 *  - namespace-isolated persistence
 *  - authenticated Redis connectivity
 *  - TLS-ready infrastructure support
 *  - distributed synchronization guarantees
 *  - fault-tolerant retry orchestration
 *  - resilient connection lifecycle management
 *
 * Designed For:
 *
 *  - distributed authentication services
 *  - enterprise IAM infrastructures
 *  - API gateway ecosystems
 *  - adaptive threat-intelligence platforms
 *  - AI-assisted telemetry pipelines
 *
 * Integrated Domains:
 *
 *  - Redis caching
 *  - distributed sessions
 *  - rate limiting
 *  - refresh-token persistence
 *  - distributed locking
 *  - security telemetry propagation
 *
 * ============================================================================
 */

@Global()
@Module({
  /**
   * --------------------------------------------------------------------------
   * Module Imports
   * --------------------------------------------------------------------------
   */

  imports: [
    ConfigModule,
  ],

  /**
   * --------------------------------------------------------------------------
   * Dependency Injection Providers
   * --------------------------------------------------------------------------
   */

  providers: [
    /**
     * ------------------------------------------------------------------------
     * Redis Connection Provider
     * ------------------------------------------------------------------------
     */

    {
      provide: Redis,

      inject: [
        ConfigService,
      ],

      useFactory: async (
        configService: ConfigService,
      ): Promise<Redis> => {
        /**
         * --------------------------------------------------------------------
         * Redis Client Initialization
         * --------------------------------------------------------------------
         */

        const client =
          new Redis({
            host:
              configService.get<string>(
                'redis.host',
              ),

            port:
              configService.get<number>(
                'redis.port',
              ),

            username:
              configService.get<string>(
                'redis.username',
              ),

            password:
              configService.get<string>(
                'redis.password',
              ),

            db:
              configService.get<number>(
                'redis.db',
              ),

            keyPrefix:
              configService.get<string>(
                'redis.keyPrefix',
              ),

            connectTimeout:
              configService.get<number>(
                'redis.connectTimeout',
              ),

            maxRetriesPerRequest:
              configService.get<number>(
                'redis.maxRetriesPerRequest',
              ),

            lazyConnect:
              true,

            enableReadyCheck:
              true,

            enableOfflineQueue:
              true,

            keepAlive:
              configService.get<number>(
                'redis.keepAlive',
              ),

            retryStrategy:
              configService.get(
                'redis.retryStrategy',
              ),

            tls:
              configService.get(
                'redis.tls',
              ),
          });

        /**
         * --------------------------------------------------------------------
         * Runtime Event Telemetry
         * --------------------------------------------------------------------
         */

        const logger =
          new Logger(
            'RedisConnection',
          );

        client.on(
          'connect',
          () => {
            logger.log(
              'Redis connection established',
            );
          },
        );

        client.on(
          'ready',
          () => {
            logger.log(
              'Redis infrastructure ready',
            );
          },
        );

        client.on(
          'error',
          (error) => {
            logger.error(
              `Redis error: ${error.message}`,
            );
          },
        );

        client.on(
          'reconnecting',
          () => {
            logger.warn(
              'Redis reconnecting...',
            );
          },
        );

        client.on(
          'close',
          () => {
            logger.warn(
              'Redis connection closed',
            );
          },
        );

        /**
         * --------------------------------------------------------------------
         * Explicit Connection Bootstrap
         * --------------------------------------------------------------------
         */

        await client.connect();

        return client;
      },
    },

    /**
     * ------------------------------------------------------------------------
     * Infrastructure Services
     * ------------------------------------------------------------------------
     */

    RedisService,

    DistributedLockService,
  ],

  /**
   * --------------------------------------------------------------------------
   * Exported Infrastructure
   * --------------------------------------------------------------------------
   */

  exports: [
    Redis,

    RedisService,

    DistributedLockService,
  ],
})

/**
 * ============================================================================
 * Redis Lifecycle Infrastructure Manager
 * ============================================================================
 */

export class RedisModule
  implements
    OnModuleInit,
    OnModuleDestroy
{
  private readonly logger =
    new Logger(
      RedisModule.name,
    );

  constructor(
    private readonly redis: Redis,
  ) {}

  /**
   * --------------------------------------------------------------------------
   * Runtime Initialization Hook
   * --------------------------------------------------------------------------
   */

  async onModuleInit(): Promise<void> {
    /**
     * ------------------------------------------------------------------------
     * Connectivity Verification
     * ------------------------------------------------------------------------
     */

    const pong =
      await this.redis.ping();

    if (pong !== 'PONG') {
      throw new Error(
        'Redis infrastructure verification failed',
      );
    }

    this.logger.log(
      'Redis infrastructure initialized successfully',
    );
  }

  /**
   * --------------------------------------------------------------------------
   * Graceful Shutdown Hook
   * --------------------------------------------------------------------------
   */

  async onModuleDestroy(): Promise<void> {
    /**
     * ------------------------------------------------------------------------
     * Connection Teardown
     * ------------------------------------------------------------------------
     */

    await this.redis.quit();

    this.logger.log(
      'Redis infrastructure shutdown completed',
    );
  }
}