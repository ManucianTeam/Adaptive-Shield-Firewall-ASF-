// apps/ai-engine/src/analyzers/entropy.analyzer.ts

import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class EntropyAnalyzer {
  private readonly logger = new Logger(
    EntropyAnalyzer.name,
  );

  // =========================
  // SHANNON ENTROPY
  // =========================

  calculateEntropy(
    value: string,
  ): number {
    if (!value || value.length === 0) {
      return 0;
    }

    const frequency: Record<
      string,
      number
    > = {};

    // =========================
    // CHARACTER FREQUENCY
    // =========================

    for (const char of value) {
      frequency[char] =
        (frequency[char] || 0) + 1;
    }

    // =========================
    // ENTROPY
    // =========================

    let entropy = 0;

    const length = value.length;

    for (const char in frequency) {
      const probability =
        frequency[char] / length;

      entropy -=
        probability *
        Math.log2(probability);
    }

    return entropy;
  }

  // =========================
  // TOKEN ANALYSIS
  // =========================

  analyzeToken(
    token: string,
  ): {
    entropy: number;
    suspicious: boolean;
  } {
    const entropy =
      this.calculateEntropy(token);

    // =========================
    // HEURISTIC
    // =========================

    const suspicious =
      entropy > 4.5;

    if (suspicious) {
      this.logger.warn(
        `[ENTROPY] suspicious token => entropy=${entropy.toFixed(
          2,
        )}`,
      );
    }

    return {
      entropy,
      suspicious,
    };
  }

  // =========================
  // RANDOMNESS SCORE
  // =========================

  randomnessScore(
    value: string,
  ): number {
    const entropy =
      this.calculateEntropy(value);

    const maxEntropy = 8;

    return Math.min(
      (entropy / maxEntropy) * 100,
      100,
    );
  }

  // =========================
  // BASE64 DETECTION
  // =========================

  isBase64(
    value: string,
  ): boolean {
    const base64Regex =
      /^[A-Za-z0-9+/=]+$/;

    return (
      value.length % 4 === 0 &&
      base64Regex.test(value)
    );
  }

  // =========================
  // HEX DETECTION
  // =========================

  isHex(
    value: string,
  ): boolean {
    return /^[0-9a-fA-F]+$/.test(
      value,
    );
  }

  // =========================
  // RANDOM STRING DETECTION
  // =========================

  isRandomString(
    value: string,
  ): boolean {
    const entropy =
      this.calculateEntropy(value);

    return (
      entropy > 4.2 &&
      value.length > 16
    );
  }
}