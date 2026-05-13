// apps/auth-service/src/redis/distributed-lock.service.ts

import {
  Injectable,
  Logger,
} from '@nestjs/common';

import {
  ConfigService,
} from '@nestjs/config';

import Redis from 'ioredis';

import { randomUUID } from 'crypto';

/**
 * ============================================================================
 * Distributed Lock Service
 * ============================================================================
 *
 * Enterprise-grade distributed synchronization layer engineered for
 * high-concurrency authentication infrastructures and adaptive Zero Trust
 * platforms.
 *
 * Core Responsibilities:
 *
 *  - distributed mutual exclusion
 *  - race-condition prevention
 *  - atomic authentication coordination
 *  - cross-instance synchronization
 *  - session consistency protection
 *  - concurrent workflow serialization
 *
 * Security Architecture:
 *
 *  - token-based lock ownership
 *  - atomic Redis synchronization
 *  - expiration-aware deadlock prevention
 *  - ownership-verified lock release
 *  - distributed consistency guarantees
 *  - failure-resilient coordination
 *
 * Designed For:
 *
 *  - distributed authentication services
 *  - refresh-token rotation
 *  - concurrent session management
 *  - brute-force mitigation pipelines
 *  - AI-assisted threat orchestration
 *  - multi-instance microservice clusters
 *
 * Integrated Domains:
 *
 *  - Redis distributed locking
 *  - session isolation
 *  - transactional coordination
 *  - authentication serialization
 *  - request concurrency control
 *  - distributed security workflows
 *
 * ============================================================================
 */

@Injectable()
export class DistributedLockService {
  /**
   * --------------------------------------------------------------------------
   * Internal Logger
   * --------------------------------------------------------------------------
   */

  private readonly logger =
    new Logger(
      DistributedLockService.name,
    );

  /**
   * --------------------------------------------------------------------------
   * Redis Lock Prefix Namespace
   * --------------------------------------------------------------------------
   */

  private readonly lockPrefix =
    'asf:lock';

  /**
   * --------------------------------------------------------------------------
   * Default Lock TTL
   * --------------------------------------------------------------------------
   */

  private readonly defaultTtl =
    5000;

  constructor(
    private readonly redis: Redis,

    private readonly configService: ConfigService,
  ) {}

  /**
   * ==========================================================================
   * Acquire Distributed Lock
   * ==========================================================================
   *
   * Establishes an atomic distributed lock using Redis SET NX semantics.
   *
   * Security Guarantees:
   *
   *  - exclusive ownership
   *  - expiration-aware deadlock mitigation
   *  - cross-instance synchronization
   *  - race-condition prevention
   *
   * ==========================================================================
   */

  async acquireLock(
    resource: string,

    ttl: number =
      this.defaultTtl,
  ): Promise<
    | {
        key: string;
        token: string;
      }
    | null
  > {
    /**
     * ------------------------------------------------------------------------
     * Distributed Lock Key
     * ------------------------------------------------------------------------
     */

    const key =
      `${this.lockPrefix}:${resource}`;

    /**
     * ------------------------------------------------------------------------
     * Ownership Token
     * ------------------------------------------------------------------------
     */

    const token =
      randomUUID();

    /**
     * ------------------------------------------------------------------------
     * Atomic Lock Acquisition
     * ------------------------------------------------------------------------
     */

    const result =
      await this.redis.set(
        key,
        token,
        'PX',
        ttl,
        'NX',
      );

    /**
     * ------------------------------------------------------------------------
     * Lock Contention
     * ------------------------------------------------------------------------
     */

    if (result !== 'OK') {
      this.logger.warn(
        `Failed to acquire distributed lock for resource: ${resource}`,
      );

      return null;
    }

    /**
     * ------------------------------------------------------------------------
     * Lock Established
     * ------------------------------------------------------------------------
     */

    this.logger.debug(
      `Distributed lock acquired: ${resource}`,
    );

    return {
      key,
      token,
    };
  }

  /**
   * ==========================================================================
   * Release Distributed Lock
   * ==========================================================================
   *
   * Releases the distributed lock only if ownership matches the provided
   * synchronization token.
   *
   * Security Guarantees:
   *
   *  - ownership validation
   *  - atomic release semantics
   *  - stale-lock protection
   *  - cross-instance safety
   *
   * ==========================================================================
   */

  async releaseLock(
    key: string,

    token: string,
  ): Promise<boolean> {
    /**
     * ------------------------------------------------------------------------
     * Ownership Validation Script
     * ------------------------------------------------------------------------
     */

    const script = `
      if redis.call("GET", KEYS[1]) == ARGV[1]
      then
        return redis.call("DEL", KEYS[1])
      else
        return 0
      end
    `;

    /**
     * ------------------------------------------------------------------------
     * Atomic Ownership Release
     * ------------------------------------------------------------------------
     */

    const result =
      await this.redis.eval(
        script,
        1,
        key,
        token,
      );

    /**
     * ------------------------------------------------------------------------
     * Release Outcome
     * ------------------------------------------------------------------------
     */

    const released =
      Number(result) === 1;

    if (released) {
      this.logger.debug(
        `Distributed lock released: ${key}`,
      );
    } else {
      this.logger.warn(
        `Distributed lock release rejected due to ownership mismatch: ${key}`,
      );
    }

    return released;
  }

  /**
   * ==========================================================================
   * Execute Critical Section
   * ==========================================================================
   *
   * Executes a protected asynchronous operation under distributed lock
   * isolation.
   *
   * Guarantees:
   *
   *  - serialized execution
   *  - automatic cleanup
   *  - ownership-safe release
   *  - concurrency isolation
   *
   * ==========================================================================
   */

  async withLock<T>(
    resource: string,

    callback: () => Promise<T>,

    ttl: number =
      this.defaultTtl,
  ): Promise<T> {
    /**
     * ------------------------------------------------------------------------
     * Acquire Lock
     * ------------------------------------------------------------------------
     */

    const lock =
      await this.acquireLock(
        resource,
        ttl,
      );

    if (!lock) {
      throw new Error(
        `Unable to acquire distributed lock for resource: ${resource}`,
      );
    }

    try {
      /**
       * ----------------------------------------------------------------------
       * Execute Protected Workflow
       * ----------------------------------------------------------------------
       */

      return await callback();
    } finally {
      /**
       * ----------------------------------------------------------------------
       * Guaranteed Lock Cleanup
       * ----------------------------------------------------------------------
       */

      await this.releaseLock(
        lock.key,
        lock.token,
      );
    }
  }

  /**
   * ==========================================================================
   * Extend Lock Lifetime
   * ==========================================================================
   *
   * Refreshes lock expiration if ownership validation succeeds.
   *
   * ==========================================================================
   */

  async extendLock(
    key: string,

    token: string,

    ttl: number,
  ): Promise<boolean> {
    /**
     * ------------------------------------------------------------------------
     * Ownership-Aware TTL Refresh
     * ------------------------------------------------------------------------
     */

    const script = `
      if redis.call("GET", KEYS[1]) == ARGV[1]
      then
        return redis.call("PEXPIRE", KEYS[1], ARGV[2])
      else
        return 0
      end
    `;

    const result =
      await this.redis.eval(
        script,
        1,
        key,
        token,
        ttl,
      );

    return Number(result) === 1;
  }

  /**
   * ==========================================================================
   * Lock State Inspection
   * ==========================================================================
   */

  async isLocked(
    resource: string,
  ): Promise<boolean> {
    const key =
      `${this.lockPrefix}:${resource}`;

    const exists =
      await this.redis.exists(
        key,
      );

    return exists === 1;
  }
}