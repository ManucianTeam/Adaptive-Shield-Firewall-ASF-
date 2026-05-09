// apps/ai-engine/src/common/utils/timing.utils.ts

export class TimingUtils {
  // =========================
  // NOW
  // =========================

  static now(): number {
    return Date.now();
  }

  // =========================
  // EXECUTION TIMER
  // =========================

  static measure(
    startTime: number,
  ): number {
    return Date.now() - startTime;
  }

  // =========================
  // SLEEP
  // =========================

  static async sleep(
    ms: number,
  ): Promise<void> {
    return new Promise((resolve) =>
      setTimeout(resolve, ms),
    );
  }

  // =========================
  // FORMAT MILLISECONDS
  // =========================

  static formatMs(
    ms: number,
  ): string {
    if (ms < 1000) {
      return `${ms}ms`;
    }

    const seconds = ms / 1000;

    if (seconds < 60) {
      return `${seconds.toFixed(2)}s`;
    }

    const minutes = seconds / 60;

    return `${minutes.toFixed(2)}m`;
  }

  // =========================
  // IS EXPIRED
  // =========================

  static isExpired(
    timestamp: number,
    ttl: number,
  ): boolean {
    return (
      Date.now() - timestamp > ttl
    );
  }

  // =========================
  // TIME DIFFERENCE
  // =========================

  static diff(
    start: number,
    end: number,
  ): number {
    return end - start;
  }

  // =========================
  // REQUESTS PER SECOND
  // =========================

  static requestsPerSecond(
    requestCount: number,
    durationMs: number,
  ): number {
    if (durationMs <= 0) {
      return 0;
    }

    return (
      requestCount / (durationMs / 1000)
    );
  }

  // =========================
  // REQUESTS PER MINUTE
  // =========================

  static requestsPerMinute(
    requestCount: number,
    durationMs: number,
  ): number {
    if (durationMs <= 0) {
      return 0;
    }

    return (
      requestCount / (durationMs / 60000)
    );
  }

  // =========================
  // DEBOUNCE CHECK
  // =========================

  static debounce(
    lastExecution: number,
    delay: number,
  ): boolean {
    return (
      Date.now() - lastExecution >= delay
    );
  }
}