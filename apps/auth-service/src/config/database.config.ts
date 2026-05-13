// apps/auth-service/src/config/database.config.ts

import { registerAs } from '@nestjs/config';

import {
  TypeOrmModuleOptions,
} from '@nestjs/typeorm';

/**
 * ============================================================================
 * ASF Database Configuration
 * ============================================================================
 *
 * Enterprise-grade database configuration layer engineered for distributed
 * authentication infrastructures and adaptive security platforms.
 *
 * Core Responsibilities:
 *
 *  - TypeORM configuration orchestration
 *  - environment-aware database bootstrapping
 *  - connection-pool optimization
 *  - migration lifecycle integration
 *  - distributed persistence configuration
 *  - transactional reliability enforcement
 *
 * Security Architecture:
 *
 *  - environment-isolated credentials
 *  - deterministic schema synchronization
 *  - production-safe migration policies
 *  - hardened connection handling
 *  - pool-level resilience tuning
 *  - failure-aware retry orchestration
 *
 * Designed For:
 *
 *  - enterprise authentication systems
 *  - distributed microservice infrastructures
 *  - high-concurrency API platforms
 *  - Zero Trust identity architectures
 *  - AI-assisted security ecosystems
 *
 * Supported Drivers:
 *
 *  - PostgreSQL
 *  - MySQL
 *  - MariaDB
 *  - SQLite (development/testing)
 *
 * ============================================================================
 */

export default registerAs(
  'database',

  (): TypeOrmModuleOptions => ({
    /**
     * ------------------------------------------------------------------------
     * Database Driver
     * ------------------------------------------------------------------------
     */

    type:
      (process.env.DB_TYPE ||
        'postgres') as any,

    /**
     * ------------------------------------------------------------------------
     * Connection Parameters
     * ------------------------------------------------------------------------
     */

    host:
      process.env.DB_HOST ||
      'localhost',

    port:
      Number(
        process.env.DB_PORT ||
        5432,
      ),

    username:
      process.env.DB_USERNAME ||
      'postgres',

    password:
      process.env.DB_PASSWORD ||
      'postgres',

    database:
      process.env.DB_NAME ||
      'asf_auth',

    /**
     * ------------------------------------------------------------------------
     * Entity Discovery
     * ------------------------------------------------------------------------
     */

    autoLoadEntities:
      true,

    entities: [
      __dirname +
        '/../**/*.entity.{ts,js}',
    ],

    /**
     * ------------------------------------------------------------------------
     * Migration Infrastructure
     * ------------------------------------------------------------------------
     */

    migrations: [
      __dirname +
        '/../database/migrations/*.{ts,js}',
    ],

    migrationsTableName:
      'typeorm_migrations',

    /**
     * ------------------------------------------------------------------------
     * Schema Synchronization
     * ------------------------------------------------------------------------
     *
     * WARNING:
     * Disabled in production environments to preserve deterministic schema
     * control and migration integrity.
     */

    synchronize:
      process.env.NODE_ENV !==
      'production' &&
      process.env.DB_SYNC ===
        'true',

    /**
     * ------------------------------------------------------------------------
     * Query Logging
     * ------------------------------------------------------------------------
     */

    logging:
      process.env.DB_LOGGING ===
      'true',

    /**
     * ------------------------------------------------------------------------
     * Connection Pool Optimization
     * ------------------------------------------------------------------------
     */

    extra: {
      max:
        Number(
          process.env
            .DB_POOL_SIZE || 20,
        ),

      min:
        Number(
          process.env
            .DB_POOL_MIN || 5,
        ),

      idleTimeoutMillis:
        Number(
          process.env
            .DB_IDLE_TIMEOUT ||
            30000,
        ),

      connectionTimeoutMillis:
        Number(
          process.env
            .DB_CONNECTION_TIMEOUT ||
            5000,
        ),
    },

    /**
     * ------------------------------------------------------------------------
     * Retry Orchestration
     * ------------------------------------------------------------------------
     */

    retryAttempts:
      Number(
        process.env
          .DB_RETRY_ATTEMPTS ||
          5,
      ),

    retryDelay:
      Number(
        process.env
          .DB_RETRY_DELAY ||
          3000,
      ),

    /**
     * ------------------------------------------------------------------------
     * TLS / SSL Security
     * ------------------------------------------------------------------------
     */

    ssl:
      process.env.DB_SSL ===
      'true'
        ? {
            rejectUnauthorized:
              false,
          }
        : false,

    /**
     * ------------------------------------------------------------------------
     * Production Stability
     * ------------------------------------------------------------------------
     */

    keepConnectionAlive:
      true,

    /**
     * ------------------------------------------------------------------------
     * Timezone Consistency
     * ------------------------------------------------------------------------
     */

    timezone:
      'Z',
  }),
);