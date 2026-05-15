/* ============================================================
 * ASF — Adaptive Shield Firewall
 * Distributed Redis Lock Service
 * File: redis-lock.service.ts
 * ============================================================
 *
 * PURPOSE:
 * Provides distributed synchronization primitives
 * using Redis-based locking semantics.
 *
 * This service is responsible for:
 * - distributed mutex locking
 * - race-condition prevention
 * - atomic execution coordination
 * - cross-instance synchronization
 * - critical section protection
 *
 * ============================================================
 *
 * SECURITY OBJECTIVES:
 * - Prevent concurrent mutation corruption
 * - Avoid duplicate processing execution
 * - Coordinate clustered enforcement layers
 * - Ensure distributed consistency
 * - Mitigate replay execution races
 *
 * ============================================================
 *
 * DESIGN PRINCIPLES:
 * - Atomic Redis operations
 * - Low-latency lock acquisition
 * - Fail-safe expiration strategy
 * - Horizontal scalability
 * - Deterministic unlock ownership
 *
 * ============================================================
 *
 * IMPORTANT:
 * Redis locks are advisory synchronization tools.
 *
 * NEVER:
 * - assume lock permanence
 * - use infinite TTL locks
 * - unlock foreign ownership tokens
 * - rely solely on Redis for consistency guarantees
 *
 * ============================================================
 */

import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';

import Redis from 'ioredis';

import { randomUUID } from 'crypto';

/**
 * ============================================================
 * Lock Acquisition Result
 * ============================================================
 */

export interface LockResult {
  acquired: boolean;

  lockKey: string;

  token?: string;

  expiresIn?: number;
}

/**
 * ============================================================
 * Redis Lock Service
 * ============================================================
 */

@Injectable()
export class RedisLockService implements OnModuleDestroy {
  /**
   * ==========================================================
   * Logger
   * ==========================================================
   */

  private readonly logger = new Logger(RedisLockService.name);

  /**
   * ==========================================================
   * Redis Client
   * ==========================================================
   */

  private readonly redis: Redis;

  /**
   * ==========================================================
   * Default Configuration
   * ==========================================================
   */

  private readonly DEFAULT_LOCK_TTL = 15_000;

  /**
   * ==========================================================
   * Constructor
   * ==========================================================
   */

  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',

      port: Number(process.env.REDIS_PORT || 6379),

      password: process.env.REDIS_PASSWORD,

      lazyConnect: true,

      maxRetriesPerRequest: 3,

      enableReadyCheck: true,
    });

    this.redis.on('connect', () => {
      this.logger.log('🔐 Redis lock engine connected');
    });

    this.redis.on('error', (error) => {
      this.logger.error('Redis connection error', error);
    });
  }

  /**
   * ==========================================================
   * Acquire Distributed Lock
   * ==========================================================
   *
   * Uses:
   * SET key value NX PX ttl
   *
   * Guarantees:
   * - atomic lock acquisition
   * - ownership token isolation
   * ==========================================================
   */

  async acquireLock(
    key: string,

    ttl = this.DEFAULT_LOCK_TTL,
  ): Promise<LockResult> {
    const token = randomUUID();

    const lockKey = this.buildLockKey(key);

    try {
      const result = await this.redis.set(lockKey, token, 'PX', ttl, 'NX');

      const acquired = result === 'OK';

      /**
       * ======================================================
       * Telemetry
       * ======================================================
       */

      this.logger.log({
        event: 'LOCK_ACQUIRE_ATTEMPT',

        lockKey,

        acquired,

        ttl,

        timestamp: Date.now(),
      });

      return {
        acquired,

        lockKey,

        token: acquired ? token : undefined,

        expiresIn: acquired ? ttl : undefined,
      };
    } catch (error) {
      this.logger.error({
        event: 'LOCK_ACQUIRE_FAILURE',

        lockKey,

        error,
      });

      return {
        acquired: false,

        lockKey,
      };
    }
  }

  /**
   * ==========================================================
   * Release Distributed Lock
   * ==========================================================
   *
   * IMPORTANT:
   * Unlock only if ownership token matches.
   *
   * Prevents:
   * - accidental foreign unlocks
   * - race-condition unlock corruption
   * ==========================================================
   */

  async releaseLock(
    key: string,

    token: string,
  ): Promise<boolean> {
    const lockKey = this.buildLockKey(key);

    /**
     * ========================================================
     * Atomic Ownership Validation Script
     * ========================================================
     */

    const lua = `
      if redis.call("GET", KEYS[1]) == ARGV[1]
      then
        return redis.call("DEL", KEYS[1])
      else
        return 0
      end
    `;

    try {
      const result = await this.redis.eval(lua, 1, lockKey, token);

      const released = result === 1;

      this.logger.log({
        event: 'LOCK_RELEASE',

        lockKey,

        released,

        timestamp: Date.now(),
      });

      return released;
    } catch (error) {
      this.logger.error({
        event: 'LOCK_RELEASE_FAILURE',

        lockKey,

        error,
      });

      return false;
    }
  }

  /**
   * ==========================================================
   * Execute Within Lock
   * ==========================================================
   *
   * Utility wrapper:
   * - acquire lock
   * - execute callback
   * - auto-release
   * ==========================================================
   */

  async withLock<T>(
    key: string,

    callback: () => Promise<T>,

    ttl = this.DEFAULT_LOCK_TTL,
  ): Promise<T | null> {
    const lock = await this.acquireLock(key, ttl);

    if (!lock.acquired || !lock.token) {
      this.logger.warn({
        event: 'LOCK_CONTENTION',

        lockKey: lock.lockKey,
      });

      return null;
    }

    try {
      return await callback();
    } finally {
      await this.releaseLock(key, lock.token);
    }
  }

  /**
   * ==========================================================
   * Check Lock Status
   * ==========================================================
   */

  async isLocked(key: string): Promise<boolean> {
    const lockKey = this.buildLockKey(key);

    const exists = await this.redis.exists(lockKey);

    return exists === 1;
  }

  /**
   * ==========================================================
   * Generate Namespaced Lock Key
   * ==========================================================
   */

  private buildLockKey(key: string): string {
    return `asf:lock:${key}`;
  }

  /**
   * ==========================================================
   * Graceful Shutdown
   * ==========================================================
   */

  async onModuleDestroy(): Promise<void> {
    await this.redis.quit();

    this.logger.warn('🛑 Redis lock engine disconnected');
  }
}
