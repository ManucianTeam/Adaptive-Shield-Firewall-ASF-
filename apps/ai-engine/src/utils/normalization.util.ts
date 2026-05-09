// apps/ai-engine/src/common/utils/normalization.utils.ts

export class NormalizationUtils {
  // =========================
  // MIN MAX NORMALIZATION
  // =========================

  static minMax(
    value: number,
    min: number,
    max: number,
  ): number {
    if (max - min === 0) {
      return 0;
    }

    return (value - min) / (max - min);
  }

  // =========================
  // NORMALIZE TO PERCENT
  // =========================

  static toPercent(
    value: number,
    max: number,
  ): number {
    if (max === 0) {
      return 0;
    }

    return (value / max) * 100;
  }

  // =========================
  // CLAMP 0 -> 1
  // =========================

  static clamp01(
    value: number,
  ): number {
    if (value < 0) {
      return 0;
    }

    if (value > 1) {
      return 1;
    }

    return value;
  }

  // =========================
  // CLAMP 0 -> 100
  // =========================

  static clamp100(
    value: number,
  ): number {
    if (value < 0) {
      return 0;
    }

    if (value > 100) {
      return 100;
    }

    return value;
  }

  // =========================
  // LOG NORMALIZATION
  // =========================

  static logNormalize(
    value: number,
  ): number {
    return Math.log1p(value);
  }

  // =========================
  // Z-SCORE NORMALIZATION
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

  // =========================
  // SIGMOID NORMALIZATION
  // =========================

  static sigmoid(
    value: number,
  ): number {
    return (
      1 / (1 + Math.exp(-value))
    );
  }

  // =========================
  // SOFTMAX
  // =========================

  static softmax(
    values: number[],
  ): number[] {
    const exps = values.map((v) =>
      Math.exp(v),
    );

    const sum = exps.reduce(
      (a, b) => a + b,
      0,
    );

    return exps.map(
      (exp) => exp / sum,
    );
  }

  // =========================
  // VECTOR NORMALIZATION
  // =========================

  static normalizeVector(
    values: number[],
  ): number[] {
    const magnitude = Math.sqrt(
      values.reduce(
        (sum, v) => sum + v * v,
        0,
      ),
    );

    if (magnitude === 0) {
      return values;
    }

    return values.map(
      (v) => v / magnitude,
    );
  }
}