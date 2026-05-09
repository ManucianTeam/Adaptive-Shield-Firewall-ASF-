// apps/ai-engine/src/common/utils/vector.utils.ts

export class VectorUtils {
  // =========================
  // DOT PRODUCT
  // =========================

  static dot(
    a: number[],
    b: number[],
  ): number {
    if (a.length !== b.length) {
      throw new Error(
        'Vectors must have same length',
      );
    }

    return a.reduce(
      (sum, value, index) =>
        sum + value * b[index],
      0,
    );
  }

  // =========================
  // MAGNITUDE
  // =========================

  static magnitude(
    vector: number[],
  ): number {
    return Math.sqrt(
      vector.reduce(
        (sum, value) =>
          sum + value * value,
        0,
      ),
    );
  }

  // =========================
  // NORMALIZE VECTOR
  // =========================

  static normalize(
    vector: number[],
  ): number[] {
    const mag =
      this.magnitude(vector);

    if (mag === 0) {
      return vector;
    }

    return vector.map(
      (value) => value / mag,
    );
  }

  // =========================
  // COSINE SIMILARITY
  // =========================

  static cosineSimilarity(
    a: number[],
    b: number[],
  ): number {
    const dot =
      this.dot(a, b);

    const magA =
      this.magnitude(a);

    const magB =
      this.magnitude(b);

    if (magA === 0 || magB === 0) {
      return 0;
    }

    return dot / (magA * magB);
  }

  // =========================
  // EUCLIDEAN DISTANCE
  // =========================

  static euclideanDistance(
    a: number[],
    b: number[],
  ): number {
    if (a.length !== b.length) {
      throw new Error(
        'Vectors must have same length',
      );
    }

    const sum = a.reduce(
      (acc, value, index) => {
        const diff =
          value - b[index];

        return acc + diff * diff;
      },
      0,
    );

    return Math.sqrt(sum);
  }

  // =========================
  // MANHATTAN DISTANCE
  // =========================

  static manhattanDistance(
    a: number[],
    b: number[],
  ): number {
    if (a.length !== b.length) {
      throw new Error(
        'Vectors must have same length',
      );
    }

    return a.reduce(
      (sum, value, index) =>
        sum +
        Math.abs(
          value - b[index],
        ),
      0,
    );
  }

  // =========================
  // VECTOR ADD
  // =========================

  static add(
    a: number[],
    b: number[],
  ): number[] {
    if (a.length !== b.length) {
      throw new Error(
        'Vectors must have same length',
      );
    }

    return a.map(
      (value, index) =>
        value + b[index],
    );
  }

  // =========================
  // VECTOR SUBTRACT
  // =========================

  static subtract(
    a: number[],
    b: number[],
  ): number[] {
    if (a.length !== b.length) {
      throw new Error(
        'Vectors must have same length',
      );
    }

    return a.map(
      (value, index) =>
        value - b[index],
    );
  }

  // =========================
  // SCALAR MULTIPLY
  // =========================

  static scalarMultiply(
    vector: number[],
    scalar: number,
  ): number[] {
    return vector.map(
      (value) => value * scalar,
    );
  }

  // =========================
  // VECTOR AVERAGE
  // =========================

  static average(
    vectors: number[][],
  ): number[] {
    if (!vectors.length) {
      return [];
    }

    const length =
      vectors[0].length;

    const result =
      new Array(length).fill(0);

    vectors.forEach((vector) => {
      for (
        let i = 0;
        i < length;
        i++
      ) {
        result[i] += vector[i];
      }
    });

    return result.map(
      (value) =>
        value / vectors.length,
    );
  }
}