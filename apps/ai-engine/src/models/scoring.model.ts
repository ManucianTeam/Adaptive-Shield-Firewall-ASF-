// apps/gateway/src/database/models/scoring.model.ts

import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type ScoringDocument = Scoring & Document;

@Schema({
  timestamps: true,
  collection: 'security_scores',
})
export class Scoring {
  @Prop({ required: true })
  ip: string;

  @Prop({ default: null })
  userId?: string;

  @Prop({ default: null })
  fingerprint?: string;

  @Prop({ default: 0 })
  trustScore: number;
  // 0 -> 100

  @Prop({ default: 0 })
  riskScore: number;
  // 0 -> 100

  @Prop({ default: 'safe' })
  status: 'safe' | 'warning' | 'danger' | 'critical';

  @Prop({ type: [String], default: [] })
  reasons: string[];
  // vd:
  // TOO_MANY_REQUESTS
  // VPN_DETECTED
  // BOT_ACTIVITY
  // TOKEN_SPAM
  // SUSPICIOUS_PATTERN

  @Prop({ default: 0 })
  anomalyCount: number;

  @Prop({ default: 0 })
  blockedCount: number;

  @Prop({ default: 0 })
  requestCount: number;

  @Prop({ default: false })
  isVpn: boolean;

  @Prop({ default: false })
  isTor: boolean;

  @Prop({ default: false })
  isProxy: boolean;

  @Prop({ default: false })
  blacklisted: boolean;

  @Prop({ default: null })
  country?: string;

  @Prop({ default: null })
  city?: string;

  @Prop({ default: null })
  isp?: string;

  @Prop({ type: Object, default: {} })
  metadata: Record<string, any>;

  @Prop({ default: Date.now })
  lastCalculatedAt: Date;
}

export const ScoringSchema = SchemaFactory.createForClass(Scoring);

// INDEXES
ScoringSchema.index({ ip: 1 });
ScoringSchema.index({ userId: 1 });
ScoringSchema.index({ trustScore: -1 });
ScoringSchema.index({ riskScore: -1 });
ScoringSchema.index({ blacklisted: 1 });
ScoringSchema.index({ status: 1 });
ScoringSchema.index({ lastCalculatedAt: -1 });