// apps/auth-service/src/users/entities/user.entity.ts

import {
  BeforeInsert,
  BeforeUpdate,
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity({
  name: 'users',
})
export class UserEntity {
  // ==========================================================================
  // Primary Identifier
  // ==========================================================================

  @PrimaryGeneratedColumn('uuid')
  id: string;

  // ==========================================================================
  // Username
  // ==========================================================================

  @Index({
    unique: true,
  })
  @Column({
    type: 'varchar',
    length: 32,
    unique: true,
  })
  username: string;

  // ==========================================================================
  // Email
  // ==========================================================================

  @Index({
    unique: true,
  })
  @Column({
    type: 'varchar',
    length: 120,
    unique: true,
  })
  email: string;

  // ==========================================================================
  // Password Hash
  // ==========================================================================

  @Column({
    type: 'varchar',
    select: false,
  })
  password: string;

  // ==========================================================================
  // Display Name
  // ==========================================================================

  @Column({
    type: 'varchar',
    length: 64,
    nullable: true,
  })
  displayName?: string;

  // ==========================================================================
  // Roles
  // ==========================================================================

  @Column({
    type: 'simple-array',
    default: 'user',
  })
  roles: string[];

  // ==========================================================================
  // Phone Number
  // ==========================================================================

  @Column({
    type: 'varchar',
    length: 20,
    nullable: true,
  })
  phoneNumber?: string;

  // ==========================================================================
  // Avatar URL
  // ==========================================================================

  @Column({
    type: 'text',
    nullable: true,
  })
  avatarUrl?: string;

  // ==========================================================================
  // Security Flags
  // ==========================================================================

  @Column({
    type: 'boolean',
    default: true,
  })
  isActive: boolean;

  @Column({
    type: 'boolean',
    default: false,
  })
  isLocked: boolean;

  @Column({
    type: 'boolean',
    default: false,
  })
  isEmailVerified: boolean;

  // ==========================================================================
  // Login Tracking
  // ==========================================================================

  @Column({
    type: 'timestamp',
    nullable: true,
  })
  lastLoginAt?: Date;

  @Column({
    type: 'varchar',
    length: 64,
    nullable: true,
  })
  lastLoginIp?: string;

  @Column({
    type: 'varchar',
    length: 255,
    nullable: true,
  })
  lastUserAgent?: string;

  // ==========================================================================
  // Security Metrics
  // ==========================================================================

  @Column({
    type: 'int',
    default: 0,
  })
  failedLoginAttempts: number;

  @Column({
    type: 'timestamp',
    nullable: true,
  })
  lockedUntil?: Date;

  // ==========================================================================
  // Multi-Factor Authentication
  // ==========================================================================

  @Column({
    type: 'boolean',
    default: false,
  })
  mfaEnabled: boolean;

  @Column({
    type: 'varchar',
    nullable: true,
    select: false,
  })
  mfaSecret?: string;

  // ==========================================================================
  // Refresh Token Tracking
  // ==========================================================================

  @Column({
    type: 'text',
    nullable: true,
    select: false,
  })
  currentHashedRefreshToken?: string;

  // ==========================================================================
  // Soft Delete
  // ==========================================================================

  @Column({
    type: 'boolean',
    default: false,
  })
  isDeleted: boolean;

  // ==========================================================================
  // Audit Fields
  // ==========================================================================

  @CreateDateColumn({
    type: 'timestamp',
  })
  createdAt: Date;

  @UpdateDateColumn({
    type: 'timestamp',
  })
  updatedAt: Date;

  // ==========================================================================
  // Hooks
  // ==========================================================================

  @BeforeInsert()
  normalizeBeforeInsert(): void {
    this.email = this.email.toLowerCase().trim();

    this.username = this.username.trim();
  }

  @BeforeUpdate()
  normalizeBeforeUpdate(): void {
    if (this.email) {
      this.email = this.email.toLowerCase().trim();
    }

    if (this.username) {
      this.username = this.username.trim();
    }
  }
}
