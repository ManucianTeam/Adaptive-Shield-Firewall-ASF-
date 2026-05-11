// apps/gateway/src/database/models/behavior.model.ts

import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type BehaviorDocument = Behavior & Document;

@Schema({
  timestamps: true,
  collection: 'behaviors',
})
export class Behavior {
  @Prop({ required: true })
  ip: string;

  @Prop({ default: null })
  userId?: string;

  @Prop({ default: null })
  fingerprint?: string;

  @Prop({ required: true })
  endpoint: string;

  @Prop({ required: true })
  method: string;

  @Prop({ default: 0 })
  requestCount: number;

  @Prop({ default: 0 })
  failedRequests: number;

  @Prop({ default: 0 })
  successRequests: number;

  @Prop({ default: 0 })
  suspiciousScore: number;

  @Prop({ type: [String], default: [] })
  triggeredRules: string[];
  // vd:
  // RAPID_REQUESTS
  // TOKEN_ABUSE
  // BOT_PATTERN
  // SCANNER_ACTIVITY

  @Prop({ type: Object, default: {} })
  metadata: Record<string, any>;

  @Prop({ default: false })
  isBot: boolean;

  @Prop({ default: false })
  isBlocked: boolean;

  @Prop({ default: null })
  country?: string;

  @Prop({ default: null })
  city?: string;

  @Prop({ default: null })
  device?: string;

  @Prop({ default: null })
  browser?: string;

  @Prop({ default: null })
  os?: string;

  @Prop({ default: Date.now })
  lastActivityAt: Date;
}

export const BehaviorSchema = SchemaFactory.createForClass(Behavior);

// INDEXES
BehaviorSchema.index({ ip: 1 });
BehaviorSchema.index({ userId: 1 });
BehaviorSchema.index({ fingerprint: 1 });
BehaviorSchema.index({ suspiciousScore: -1 });
BehaviorSchema.index({ lastActivityAt: -1 });
BehaviorSchema.index({ ip: 1, endpoint: 1 });