// apps/gateway/src/ai-engine/interfaces/prediction.interface.ts

export interface PredictionInput {
  ip: string;

  userId?: string;

  fingerprint?: string;

  requestCount?: number;

  failedRequests?: number;

  anomalyCount?: number;

  blockedCount?: number;

  suspiciousScore?: number;

  confidenceScore?: number;

  riskScore?: number;

  behaviorMatches?: number;

  blacklistHits?: number;

  isVpn?: boolean;

  isTor?: boolean;

  isProxy?: boolean;

  isBot?: boolean;

  raceConditionDetected?: boolean;

  userAgent?: string;

  country?: string;

  metadata?: Record<string, any>;
}

export interface PredictionResult {
  prediction: "safe" | "suspicious" | "malicious" | "critical";

  confidence: number;

  riskScore: number;

  shouldBlock: boolean;

  shouldMonitor: boolean;

  reasons: string[];

  detectedPatterns: string[];

  timestamp: Date;
}
