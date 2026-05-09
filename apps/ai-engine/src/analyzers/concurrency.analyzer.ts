// apps/ai-engine/src/analyzers/concurrency.analyzer.ts

import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class ConcurrencyAnalyzer {
  private readonly logger = new Logger(
    ConcurrencyAnalyzer.name,
  );

  // =========================
  // ACTIVE REQUEST TRACKER
  // =========================

  private readonly activeRequests =
    new Map<
      string,
      {
        count: number;
        firstSeen: number;
        lastSeen: number;
      }
    >();

  // =========================
  // TRACK REQUEST
  // =========================

  track(
    key: string,
  ): {
    concurrentRequests: number;
    suspicious: boolean;
  } {
    const now = Date.now();

    const current =
      this.activeRequests.get(key);

    // =========================
    // FIRST REQUEST
    // =========================

    if (!current) {
      this.activeRequests.set(key, {
        count: 1,
        firstSeen: now,
        lastSeen: now,
      });

      return {
        concurrentRequests: 1,
        suspicious: false,
      };
    }

    // =========================
    // UPDATE
    // =========================

    current.count += 1;
    current.lastSeen = now;

    this.activeRequests.set(
      key,
      current,
    );

    // =========================
    // DETECT
    // =========================

    const suspicious =
      current.count >= 10;

    if (suspicious) {
      this.logger.warn(
        `[CONCURRENCY] ${key} => ${current.count} concurrent requests`,
      );
    }

    return {
      concurrentRequests:
        current.count,
      suspicious,
    };
  }

  // =========================
  // RELEASE REQUEST
  // =========================

  release(key: string): void {
    const current =
      this.activeRequests.get(key);

    if (!current) {
      return;
    }

    current.count -= 1;

    if (current.count <= 0) {
      this.activeRequests.delete(key);

      return;
    }

    this.activeRequests.set(
      key,
      current,
    );
  }

  // =========================
  // GET ACTIVE COUNT
  // =========================

  getActiveCount(
    key: string,
  ): number {
    return (
      this.activeRequests.get(key)
        ?.count || 0
    );
  }

  // =========================
  // CLEANUP OLD ENTRIES
  // =========================

  cleanup(
    maxAgeMs = 60_000,
  ): void {
    const now = Date.now();

    for (const [
      key,
      value,
    ] of this.activeRequests.entries()) {
      if (
        now - value.lastSeen >
        maxAgeMs
      ) {
        this.activeRequests.delete(
          key,
        );
      }
    }
  }

  // =========================
  // CLEAR ALL
  // =========================

  clear(): void {
    this.activeRequests.clear();
  }

  // =========================
  // SIZE
  // =========================

  size(): number {
    return this.activeRequests.size;
  }
}