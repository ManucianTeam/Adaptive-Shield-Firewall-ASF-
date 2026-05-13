// apps/auth-service/src/database/database.module.ts

import {
  Global,
  Logger,
  Module,
  OnModuleInit,
} from '@nestjs/common';

import {
  ConfigModule,
  ConfigService,
} from '@nestjs/config';

import {
  TypeOrmModule,
} from '@nestjs/typeorm';

import {
  DataSource,
} from 'typeorm';

/**
 * ============================================================================
 * ASF Database Module
 * ============================================================================
 *
 * Enterprise-grade database infrastructure module engineered for distributed
 * authentication systems, adaptive Zero Trust platforms, and high-concurrency
 * microservice environments.
 *
 * Core Responsibilities:
 *
 *  - centralized persistence orchestration
 *  - TypeORM lifecycle management
 *  - distributed database connectivity
 *  - transactional consistency enforcement
 *  - migration infrastructure integration
 *  - resilient startup validation
 *
 * Security Architecture:
 *
 *  - environment-isolated configuration
 *  - production-safe schema governance
 *  - deterministic migration execution
 *  - connection-pool hardening
 *  - fault-tolerant retry orchestration
 *  - secure credential abstraction
 *
 * Designed For:
 *
 *  - enterprise IAM infrastructures
 *  - distributed API gateways
 *  - adaptive authentication systems
 *  - AI-assisted security platforms
 *  - scalable service-oriented architectures
 *
 * Integrated Domains:
 *
 *  - PostgreSQL persistence
 *  - migration pipelines
 *  - entity discovery
 *  - transactional repositories
 *  - distributed connection pooling
 *  - runtime health verification
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
    /**
     * ------------------------------------------------------------------------
     * Environment Configuration
     * ------------------------------------------------------------------------
     */

    ConfigModule,

    /**
     * ------------------------------------------------------------------------
     * TypeORM Infrastructure Bootstrap
     * ------------------------------------------------------------------------
     */

    TypeOrmModule.forRootAsync({
      imports: [
        ConfigModule,
      ],

      inject: [
        ConfigService,
      ],

      /**
       * ----------------------------------------------------------------------
       * Dynamic Database Configuration
       * ----------------------------------------------------------------------
       */

      useFactory: async (
        configService: ConfigService,
      ) => ({
        /**
         * --------------------------------------------------------------------
         * Database Driver
         * --------------------------------------------------------------------
         */

        type:
          configService.get<
            any
          >(
            'database.type',
          ) || 'postgres',

        /**
         * --------------------------------------------------------------------
         * Connectivity
         * --------------------------------------------------------------------
         */

        host:
          configService.get<string>(
            'database.host',
          ),

        port:
          configService.get<number>(
            'database.port',
          ),

        username:
          configService.get<string>(
            'database.username',
          ),

        password:
          configService.get<string>(
            'database.password',
          ),

        database:
          configService.get<string>(
            'database.database',
          ),

        /**
         * --------------------------------------------------------------------
         * Entity Discovery
         * --------------------------------------------------------------------
         */

        autoLoadEntities:
          true,

        entities: [
          __dirname +
            '/../**/*.entity.{ts,js}',
        ],

        /**
         * --------------------------------------------------------------------
         * Migration Infrastructure
         * --------------------------------------------------------------------
         */

        migrations: [
          __dirname +
            '/migrations/*.{ts,js}',
        ],

        migrationsTableName:
          'typeorm_migrations',

        migrationsRun:
          process.env
            .DB_RUN_MIGRATIONS ===
          'true',

        /**
         * --------------------------------------------------------------------
         * Schema Synchronization
         * --------------------------------------------------------------------
         */

        synchronize:
          configService.get<boolean>(
            'database.synchronize',
          ),

        /**
         * --------------------------------------------------------------------
         * Logging Infrastructure
         * --------------------------------------------------------------------
         */

        logging:
          configService.get<boolean>(
            'database.logging',
          ),

        /**
         * --------------------------------------------------------------------
         * Retry Orchestration
         * --------------------------------------------------------------------
         */

        retryAttempts:
          configService.get<number>(
            'database.retryAttempts',
          ) || 5,

        retryDelay:
          configService.get<number>(
            'database.retryDelay',
          ) || 3000,

        /**
         * --------------------------------------------------------------------
         * Connection Pool Optimization
         * --------------------------------------------------------------------
         */

        extra:
          configService.get(
            'database.extra',
          ),

        /**
         * --------------------------------------------------------------------
         * TLS / SSL Security
         * --------------------------------------------------------------------
         */

        ssl:
          configService.get(
            'database.ssl',
          ),

        /**
         * --------------------------------------------------------------------
         * Runtime Stability
         * --------------------------------------------------------------------
         */

        keepConnectionAlive:
          true,
      }),
    }),
  ],

  /**
   * --------------------------------------------------------------------------
   * Exported Infrastructure
   * --------------------------------------------------------------------------
   */

  exports: [
    TypeOrmModule,
  ],
})

/**
 * ============================================================================
 * Runtime Database Lifecycle Manager
 * ============================================================================
 */

export class DatabaseModule
  implements OnModuleInit
{
  private readonly logger =
    new Logger(
      DatabaseModule.name,
    );

  constructor(
    private readonly dataSource: DataSource,
  ) {}

  /**
   * --------------------------------------------------------------------------
   * Database Startup Verification
   * --------------------------------------------------------------------------
   */

  async onModuleInit(): Promise<void> {
    /**
     * ------------------------------------------------------------------------
     * Connectivity Verification
     * ------------------------------------------------------------------------
     */

    if (
      this.dataSource.isInitialized
    ) {
      this.logger.log(
        'Database connection established successfully',
      );

      /**
       * ----------------------------------------------------------------------
       * Runtime Metadata Logging
       * ----------------------------------------------------------------------
       */

      this.logger.debug({
        type:
          this.dataSource.options
            .type,

        database:
          this.dataSource.options
            .database,

        entities:
          this.dataSource.entityMetadatas
            .length,

        migrations:
          this.dataSource.migrations
            .length,
      });

      return;
    }

    /**
     * ------------------------------------------------------------------------
     * Critical Failure Handling
     * ------------------------------------------------------------------------
     */

    this.logger.error(
      'Database initialization failed',
    );

    throw new Error(
      'Unable to initialize database infrastructure',
    );
  }
}