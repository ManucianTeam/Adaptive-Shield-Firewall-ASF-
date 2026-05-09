// apps/ai-engine/src/common/utils/math.utils.ts

export class MathUtils {
  // =========================
  // CLAMP
  // =========================

  static clamp(
    value: number,
    min: number,
    max: number,
  ): number {
    return Math.min(
      Math.max(value, min),
      max,
    );
  }

  // =========================
  // NORMALIZE PERCENT
  // =========================

  static normalizePercent(
    value: number,
  ): number {
    return this.clamp(value, 0, 100);
  }

  // =========================
  // AVERAGE
  // =========================

  static average(
    numbers: number[],
  ): number {
    if (!numbers.length) {
      return 0;
    }

    const total = numbers.reduce(
      (sum, num) => sum + num,
      0,
    );

    return total / numbers.length;
  }

  // =========================
  // SUM
  // =========================

  static sum(
    numbers: number[],
  ): number {
    return numbers.reduce(
      (sum, num) => sum + num,
      0,
    );
  }

  // =========================
  // RANDOM INT
  // =========================

  static randomInt(
    min: number,
    max: number,
  ): number {
    return Math.floor(
      Math.random() * (max - min + 1),
    ) + min;
  }

  // =========================
  // PERCENTAGE
  // =========================

  static percentage(
    current: number,
    total: number,
  ): number {
    if (total === 0) {
      return 0;
    }

    return (current / total) * 100;
  }

  // =========================
  // ROUND
  // =========================

  static round(
    value: number,
    precision = 2,
  ): number {
    const factor = Math.pow(
      10,
      precision,
    );

    return (
      Math.round(value * factor) / factor
    );
  }

  // =========================
  // STANDARD DEVIATION
  // =========================

  static standardDeviation(
    numbers: number[],
  ): number {
    if (!numbers.length) {
      return 0;
    }

    const avg = this.average(numbers);

    const squareDiffs = numbers.map(
      (value) => {
        const diff = value - avg;

        return diff * diff;
      },
    );

    const avgSquareDiff =
      this.average(squareDiffs);

    return Math.sqrt(avgSquareDiff);
  }

  // =========================
  // Z-SCORE
  // =========================

  static zScore(
    value: number,
    mean: number,
    stdDev: number,
  ): number {
    if (stdDev === 0) {
      return 0;
    }

    return (
      (value - mean) / stdDev
    );
  }
}