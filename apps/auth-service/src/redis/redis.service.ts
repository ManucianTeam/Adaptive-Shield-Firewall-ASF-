// apps/auth-service/src/redis/redis.service.ts

import {
  Injectable,
  Logger,
} from '@nestjs/common';

import Redis from 'ioredis';

/**
 * ============================================================================
 * ASF Redis Service
 * ============================================================================
 *
 * Enterprise-grade Redis abstraction layer engineered for distributed
 * authentication infrastructures, adaptive Zero Trust systems, and
 * high-concurrency microservice ecosystems.
 *
 * Core Responsibilities:
 *
 *  - distributed cache orchestration
 *  - session persistence abstraction
 *  - rate-limit storage management
 *  - distributed telemetry propagation
 *  - token blacklist persistence
 *  - high-performance key-value coordination
 *
 * Security Architecture:
 *
 *  - namespace-isolated storage
 *  - TTL-aware persistence control
 *  - distributed consistency guarantees
 *  - resilient failure handling
 *  - secure serialization boundaries
 *  - high-availability infrastructure support
 *
 * Designed For:
 *
 *  - distributed authentication systems
 *  - adaptive access-control platforms
 *  - AI-assisted threat telemetry
 *  - enterprise IAM infrastructures
 *  - large-scale API gateway ecosystems
 *
 * Integrated Domains:
 *
 *  - distributed sessions
 *  - refresh-token persistence
 *  - request throttling
 *  - security telemetry
 *  - behavioral analytics
 *  - distributed cache invalidation
 *
 * ============================================================================
 */

@Injectable()
export class RedisService {
  /**
   * --------------------------------------------------------------------------
   * Internal Logger
   * --------------------------------------------------------------------------
   */

  private readonly logger =
    new Logger(
      RedisService.name,
    );

  constructor(
    private readonly redis: Redis,
  ) {}

  /**
   * ==========================================================================
   * Raw Redis Client Access
   * ==========================================================================
   */

  get client(): Redis {
    return this.redis;
  }

  /**
   * ==========================================================================
   * Store Value
   * ==========================================================================
   *
   * Persists a serialized value with optional expiration semantics.
   *
   * ==========================================================================
   */

  async set<T>(
    key: string,

    value: T,

    ttlSeconds?: number,
  ): Promise<void> {
    const payload =
      JSON.stringify(value);

    if (ttlSeconds) {
      await this.redis.set(
        key,
        payload,
        'EX',
        ttlSeconds,
      );
    } else {
      await this.redis.set(
        key,
        payload,
      );
    }
  }

  /**
   * ==========================================================================
   * Retrieve Value
   * ==========================================================================
   */

  async get<T>(
    key: string,
  ): Promise<T | null> {
    const value =
      await this.redis.get(
        key,
      );

    if (!value) {
      return null;
    }

    try {
      return JSON.parse(
        value,
      ) as T;
    } catch {
      this.logger.warn(
        `Failed to deserialize Redis payload for key: ${key}`,
      );

      return null;
    }
  }

  /**
   * ==========================================================================
   * Delete Key
   * ==========================================================================
   */

  async delete(
    key: string,
  ): Promise<boolean> {
    const deleted =
      await this.redis.del(
        key,
      );

    return deleted > 0;
  }

  /**
   * ==========================================================================
   * Key Existence Validation
   * ==========================================================================
   */

  async exists(
    key: string,
  ): Promise<boolean> {
    const exists =
      await this.redis.exists(
        key,
      );

    return exists === 1;
  }

  /**
   * ==========================================================================
   * Expiration Management
   * ==========================================================================
   */

  async expire(
    key: string,

    ttlSeconds: number,
  ): Promise<boolean> {
    const updated =
      await this.redis.expire(
        key,
        ttlSeconds,
      );

    return updated === 1;
  }

  /**
   * ==========================================================================
   * Increment Counter
   * ==========================================================================
   *
   * Used for:
   *
   *  - rate limiting
   *  - login-attempt tracking
   *  - telemetry aggregation
   *  - anomaly frequency monitoring
   *
   * ==========================================================================
   */

  async increment(
    key: string,

    ttlSeconds?: number,
  ): Promise<number> {
    const value =
      await this.redis.incr(
        key,
      );

    if (
      ttlSeconds &&
      value === 1
    ) {
      await this.redis.expire(
        key,
        ttlSeconds,
      );
    }

    return value;
  }

  /**
   * ==========================================================================
   * Hash Storage
   * ==========================================================================
   */

  async setHash(
    key: string,

    values: Record<
      string,
      any
    >,
  ): Promise<void> {
    const normalized =
      Object.entries(values)
        .reduce(
          (
            acc,
            [field, value],
          ) => {
            acc[field] =
              JSON.stringify(
                value,
              );

            return acc;
          },

          {} as Record<
            string,
            string
          >,
        );

    await this.redis.hmset(
      key,
      normalized,
    );
  }

  /**
   * ==========================================================================
   * Hash Retrieval
   * ==========================================================================
   */

  async getHash<T>(
    key: string,
  ): Promise<T | null> {
    const result =
      await this.redis.hgetall(
        key,
      );

    if (
      !result ||
      Object.keys(result)
        .length === 0
    ) {
      return null;
    }

    const parsed: Record<
      string,
      any
    > = {};

    for (const [
      field,
      value,
    ] of Object.entries(
      result,
    )) {
      try {
        parsed[field] =
          JSON.parse(
            value,
          );
      } catch {
        parsed[field] =
          value;
      }
    }

    return parsed as T;
  }

  /**
   * ==========================================================================
   * Publish Distributed Event
   * ==========================================================================
   */

  async publish(
    channel: string,

    payload: unknown,
  ): Promise<void> {
    await this.redis.publish(
      channel,
      JSON.stringify(payload),
    );
  }

  /**
   * ==========================================================================
   * Subscribe To Channel
   * ==========================================================================
   */

  async subscribe(
    channel: string,

    handler: (
      payload: any,
    ) => Promise<void>,
  ): Promise<void> {
    const subscriber =
      this.redis.duplicate();

    await subscriber.connect();

    await subscriber.subscribe(
      channel,
    );

    subscriber.on(
      'message',
      async (
        incomingChannel,
        message,
      ) => {
        if (
          incomingChannel !==
          channel
        ) {
          return;
        }

        try {
          const payload =
            JSON.parse(
              message,
            );

          await handler(
            payload,
          );
        } catch (
          error: any
        ) {
          this.logger.error(
            `Redis subscription handler failed: ${error.message}`,
          );
        }
      },
    );
  }

  /**
   * ==========================================================================
   * Rate-Limit Evaluation
   * ==========================================================================
   */

  async checkRateLimit(
    key: string,

    limit: number,

    ttlSeconds: number,
  ): Promise<{
    allowed: boolean;
    remaining: number;
    current: number;
  }> {
    const current =
      await this.increment(
        key,
        ttlSeconds,
      );

    return {
      allowed:
        current <= limit,

      remaining:
        Math.max(
          limit - current,
          0,
        ),

      current,
    };
  }

  /**
   * ==========================================================================
   * Health Verification
   * ==========================================================================
   */

  async ping(): Promise<boolean> {
    try {
      const response =
        await this.redis.ping();

      return response === 'PONG';
    } catch (
      error: any
    ) {
      this.logger.error(
        `Redis health verification failed: ${error.message}`,
      );

      return false;
    }
  }

  /**
   * ==========================================================================
   * Graceful Cache Flush
   * ==========================================================================
   */

  async flushNamespace(
    prefix: string,
  ): Promise<number> {
    const keys =
      await this.redis.keys(
        `${prefix}*`,
      );

    if (
      keys.length === 0
    ) {
      return 0;
    }

    return this.redis.del(
      ...keys,
    );
  }
}