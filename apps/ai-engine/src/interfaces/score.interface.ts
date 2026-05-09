// apps/gateway/src/ai-engine/interfaces/score.interface.ts

export interface ScoreBreakdown {
  label: string;

  value: number;

  reason?: string;
}

export interface ScoreFlags {
  isVpn?: boolean;

  isTor?: boolean;

  isProxy?: boolean;

  isBot?: boolean;

  blacklisted?: boolean;

  raceConditionDetected?: boolean;
}

export interface ScoreInput {
  ip: string;

  userId?: string;

  fingerprint?: string;

  requestCount?: number;

  failedRequests?: number;

  successRequests?: number;

  anomalyCount?: number;

  blockedCount?: number;

  suspiciousScore?: number;

  confidenceScore?: number;

  behaviorScore?: number;

  blacklistHits?: number;

  userAgent?: string;

  country?: string;

  flags?: ScoreFlags;

  metadata?: Record<string, any>;
}

export interface ScoreResult {
  trustScore: number;

  riskScore: number;

  confidenceScore: number;

  level:
    | 'safe'
    | 'warning'
    | 'danger'
    | 'critical';

  shouldBlock: boolean;

  shouldMonitor: boolean;

  reasons: string[];

  breakdown: ScoreBreakdown[];

  calculatedAt: Date;
}