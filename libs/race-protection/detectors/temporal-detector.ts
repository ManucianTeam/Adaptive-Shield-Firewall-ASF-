// libs/race-protection/detectors/temporal-detector.ts

import { performance } from 'node:perf_hooks';
import crypto from 'node:crypto';
import { doesNotReject } from 'node:assert';

export interface TemporalSnapshot {
    timestamp: number;
    drift: number;
    latency: number;
    entropy: number;
    valid: boolean;
}

export interface TemporalDetectorOptions {
    maxDriftMs?: number;
    maxLatencyMs?: number;
    sampleSize?: number;
    strictMode?: boolean;
}

export class TemporalDetector {
    private readonly options: Te
