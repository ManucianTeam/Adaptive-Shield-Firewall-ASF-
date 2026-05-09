// apps/gateway/src/ai-engine/interfaces/request-pattern.interface.ts

export interface RequestPattern {
  ip: string;

  userId?: string;

  fingerprint?: string;

  endpoint: string;

  method: string;

  requestCount: number;

  failedRequests: number;

  successRequests: number;

  averageResponseTime?: number;

  requestsPerMinute?: number;

  requestsPerSecond?: number;

  suspiciousScore?: number;

  anomalyScore?: number;

  confidenceScore?: number;

  riskScore?: number;

  behaviorPatterns?: string[];
  // vd:
  // RAPID_REQUESTS
  // TOKEN_REUSE
  // BOT_ACTIVITY
  // SCANNER_PATTERN
  // RACE_CONDITION_PATTERN

  detectedAnomalies?: string[];

  headers?: Record<string, any>;

  query?: Record<string, any>;

  body?: Record<string, any>;

  userAgent?: string;

  referer?: string;

  origin?: string;

  country?: string;

  city?: string;

  device?: string;

  browser?: string;

  os?: string;

  isBot?: boolean;

  isVpn?: boolean;

  isTor?: boolean;

  isProxy?: boolean;

  blocked?: boolean;

  timestamp: Date;
}