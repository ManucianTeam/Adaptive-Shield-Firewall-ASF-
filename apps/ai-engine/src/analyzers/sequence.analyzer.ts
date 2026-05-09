// apps/ai-engine/src/analyzers/sequence.analyzer.ts

import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class SequenceAnalyzer {
  private readonly logger = new Logger(
    SequenceAnalyzer.name,
  );

  // =========================
  // REQUEST HISTORY
  // =========================

  private readonly sequences =
    new Map<string, string[]>();

  // =========================
  // TRACK EVENT
  // =========================

  track(
    key: string,
    event: string,
    maxHistory = 20,
  ): void {
    const history =
      this.sequences.get(key) || [];

    history.push(event);

    // LIMIT HISTORY
    if (history.length > maxHistory) {
      history.shift();
    }

    this.sequences.set(
      key,
      history,
    );
  }

  // =========================
  // GET HISTORY
  // =========================

  getHistory(
    key: string,
  ): string[] {
    return (
      this.sequences.get(key) || []
    );
  }

  // =========================
  // DETECT REPEATED PATTERN
  // =========================

  detectRepeatedPattern(
    key: string,
    threshold = 5,
  ): boolean {
    const history =
      this.getHistory(key);

    if (
      history.length < threshold
    ) {
      return false;
    }

    const last =
      history[history.length - 1];

    let count = 0;

    for (
      let i = history.length - 1;
      i >= 0;
      i--
    ) {
      if (history[i] === last) {
        count++;
      } else {
        break;
      }
    }

    const suspicious =
      count >= threshold;

    if (suspicious) {
      this.logger.warn(
        `[SEQUENCE] repeated pattern detected => ${last}`,
      );
    }

    return suspicious;
  }

  // =========================
  // DETECT ATTACK CHAIN
  // =========================

  detectAttackChain(
    key: string,
    chain: string[],
  ): boolean {
    const history =
      this.getHistory(key);

    if (
      history.length < chain.length
    ) {
      return false;
    }

    const recent = history.slice(
      -chain.length,
    );

    const matched =
      recent.join('|') ===
      chain.join('|');

    if (matched) {
      this.logger.warn(
        `[SEQUENCE] attack chain detected => ${chain.join(
          ' -> ',
        )}`,
      );
    }

    return matched;
  }

  // =========================
  // CLEAR HISTORY
  // =========================

  clear(
    key?: string,
  ): void {
    if (key) {
      this.sequences.delete(key);

      return;
    }

    this.sequences.clear();
  }

  // =========================
  // SIZE
  // =========================

  size(): number {
    return this.sequences.size;
  }
}