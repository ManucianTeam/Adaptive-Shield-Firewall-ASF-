// apps/ai-engine/src/analyzers/timing.analyzer.ts

import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class TimingAnalyzer {
  private readonly logger = new Logger(
    TimingAnalyzer.name,
  );

  // =========================
  // REQUEST TIMESTAMPS
  // =========================

  private readonly timestamps =
    new Map<string, number[]>();

  // =========================
  // TRACK TIMESTAMP
  // =========================

  track(
    key: string,
    maxHistory = 100,
  ): void {
    const now = Date.now();

    const history =
      this.timestamps.get(key) || [];

    history.push(now);

    // LIMIT HISTORY
    if (history.length > maxHistory) {
      history.shift();
    }

    this.timestamps.set(
      key,
      history,
    );
  }

  // =========================
  // GET HISTORY
  // =========================

  getHistory(
    key: string,
  ): number[] {
    return (
      this.timestamps.get(key) || []
    );
  }

  // =========================
  // REQUESTS PER SECOND
  // =========================

  requestsPerSecond(
    key: string,
    windowMs = 1000,
  ): number {
    const now = Date.now();

    const history =
      this.getHistory(key);

    const recent = history.filter(
      (timestamp) =>
        now - timestamp <= windowMs,
    );

    return recent.length;
  }

  // =========================
  // REQUESTS PER MINUTE
  // =========================

  requestsPerMinute(
    key: string,
    windowMs = 60_000,
  ): number {
    const now = Date.now();

    const history =
      this.getHistory(key);

    const recent = history.filter(
      (timestamp) =>
        now - timestamp <= windowMs,
    );

    return recent.length;
  }

  // =========================
  // DETECT BURST
  // =========================

  detectBurst(
    key: string,
    threshold = 20,
    windowMs = 1000,
  ): boolean {
    const rps =
      this.requestsPerSecond(
        key,
        windowMs,
      );

    const suspicious =
      rps >= threshold;

    if (suspicious) {
      this.logger.warn(
        `[TIMING] burst detected => ${key} (${rps} req/s)`,
      );
    }

    return suspicious;
  }

  // =========================
  // DETECT SPAM
  // =========================

  detectSpam(
    key: string,
    threshold = 300,
    windowMs = 60_000,
  ): boolean {
    const rpm =
      this.requestsPerMinute(
        key,
        windowMs,
      );

    const suspicious =
      rpm >= threshold;

    if (suspicious) {
      this.logger.warn(
        `[TIMING] spam detected => ${key} (${rpm} req/min)`,
      );
    }

    return suspicious;
  }

  // =========================
  // CLEAR
  // =========================

  clear(
    key?: string,
  ): void {
    if (key) {
      this.timestamps.delete(key);

      return;
    }

    this.timestamps.clear();
  }

  // =========================
  // SIZE
  // =========================

  size(): number {
    return this.timestamps.size;
  }
}