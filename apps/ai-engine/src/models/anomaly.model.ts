// apps/gateway/src/database/models/anomaly.model.ts

import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type AnomalyDocument = Anomaly & Document;

@Schema({
  timestamps: true,
  collection: 'anomalies',
})
export class Anomaly {
  @Prop({ required: true })
  ip: string;

  @Prop({ default: null })
  userId?: string;

  @Prop({ default: null })
  fingerprint?: string;

  @Prop({ required: true })
  type: string;
  // vd:
  // BOT_DETECTED
  // RATE_LIMIT
  // SUSPICIOUS_BEHAVIOR
  // INVALID_TOKEN
  // SQL_INJECTION
  // DDOS_ATTEMPT

  @Prop({ required: true })
  severity: 'low' | 'medium' | 'high' | 'critical';

  @Prop({ default: 0 })
  score: number;

  @Prop({ default: null })
  endpoint?: string;

  @Prop({ default: null })
  method?: string;

  @Prop({ type: Object, default: {} })
  metadata: Record<string, any>;

  @Prop({ default: false })
  blocked: boolean;

  @Prop({ default: null })
  country?: string;

  @Prop({ default: null })
  userAgent?: string;

  @Prop({ default: Date.now })
  detectedAt: Date;
}

export const AnomalySchema = SchemaFactory.createForClass(Anomaly);

// INDEXES
AnomalySchema.index({ ip: 1 });
AnomalySchema.index({ type: 1 });
AnomalySchema.index({ severity: 1 });
AnomalySchema.index({ detectedAt: -1 });
AnomalySchema.index({ ip: 1, detectedAt: -1 });