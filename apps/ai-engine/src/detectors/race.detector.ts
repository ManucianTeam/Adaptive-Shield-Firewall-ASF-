// apps/ai-engine/src/detectors/race.detector.ts

import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class RaceDetector {
  private readonly logger = new Logger(
    RaceDetector.name,
  );

  // =========================
  // IN-MEMORY TRACKER
  // =========================

  private readonly requestTracker =
    new Map<
      string,
      {
        count: number;
        firstRequest: number;
      }
    >();

  // =========================
  // DETECT RACE CONDITION
  // =========================

  async detect(
    key: string,
    limit = 10,
    windowMs = 1000,
  ): Promise<boolean> {
    const now = Date.now();

    const existing =
      this.requestTracker.get(key);

    // =========================
    // FIRST REQUEST
    // =========================

    if (!existing) {
      this.requestTracker.set(key, {
        count: 1,
        firstRequest: now,
      });

      return false;
    }

    // =========================
    // RESET WINDOW
    // =========================

    if (
      now - existing.firstRequest >
      windowMs
    ) {
      this.requestTracker.set(key, {
        count: 1,
        firstRequest: now,
      });

      return false;
    }

    // =========================
    // INCREASE COUNT
    // =========================

    existing.count++;

    this.requestTracker.set(key, existing);

    // =========================
    // DETECTED
    // =========================

    if (existing.count >= limit) {
      this.logger.warn(
        `[RACE DETECTED] ${key} => count=${existing.count}`,
      );

      return true;
    }

    return false;
  }

  // =========================
  // RESET KEY
  // =========================

  reset(key: string): void {
    this.requestTracker.delete(key);
  }

  // =========================
  // CLEAR ALL
  // =========================

  clear(): void {
    this.requestTracker.clear();
  }

  // =========================
  // GET TRACKER SIZE
  // =========================

  size(): number {
    return this.requestTracker.size;
  }
}