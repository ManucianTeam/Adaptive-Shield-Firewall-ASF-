// apps/gateway/src/database/models/race.model.ts

import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type RaceDocument = Race & Document;

@Schema({
  timestamps: true,
  collection: 'race_conditions',
})
export class Race {
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

  @Prop({ required: true })
  resourceId: string;
  // vd:
  // orderId
  // paymentId
  // couponId
  // scoreId

  @Prop({ default: 0 })
  concurrentRequests: number;

  @Prop({ default: false })
  detected: boolean;

  @Prop({ default: false })
  blocked: boolean;

  @Prop({ default: 'medium' })
  severity: 'low' | 'medium' | 'high' | 'critical';

  @Prop({ default: 0 })
  riskScore: number;

  @Prop({ type: [String], default: [] })
  attackPatterns: string[];
  // vd:
  // DUPLICATE_SUBMIT
  // RAPID_PARALLEL_REQUESTS
  // DOUBLE_SPENDING
  // MULTI_CLICK_ABUSE

  @Prop({ type: Object, default: {} })
  metadata: Record<string, any>;

  @Prop({ default: null })
  userAgent?: string;

  @Prop({ default: null })
  country?: string;

  @Prop({ default: Date.now })
  detectedAt: Date;
}

export const RaceSchema = SchemaFactory.createForClass(Race);

// INDEXES
RaceSchema.index({ ip: 1 });
RaceSchema.index({ resourceId: 1 });
RaceSchema.index({ detected: 1 });
RaceSchema.index({ blocked: 1 });
RaceSchema.index({ detectedAt: -1 });
RaceSchema.index({ ip: 1, resourceId: 1 });