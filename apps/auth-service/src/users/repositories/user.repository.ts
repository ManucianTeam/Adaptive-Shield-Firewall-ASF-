// apps/auth-service/src/users/repositories/user.repository.ts

import {
  Injectable,
  NotFoundException,
} from '@nestjs/common';

import {
  DataSource,
  Repository,
} from 'typeorm';

import { UserEntity } from '../entities/user.entity';

@Injectable()
export class UserRepository extends Repository<UserEntity> {
  constructor(
    private readonly dataSource: DataSource,
  ) {
    super(
      UserEntity,
      dataSource.createEntityManager(),
    );
  }

  // ==========================================================================
  // Find By ID
  // ==========================================================================

  async findById(
    id: string,
  ): Promise<UserEntity> {
    const user = await this.findOne({
      where: {
        id,
        isDeleted: false,
      },
    });

    if (!user) {
      throw new NotFoundException(
        'User not found',
      );
    }

    return user;
  }

  // ==========================================================================
  // Find By Email
  // ==========================================================================

  async findByEmail(
    email: string,
    includePassword = false,
  ): Promise<UserEntity | null> {
    const query = this.createQueryBuilder('user')
      .where('user.email = :email', {
        email: email.toLowerCase(),
      })
      .andWhere('user.isDeleted = false');

    if (includePassword) {
      query.addSelect([
        'user.password',
        'user.currentHashedRefreshToken',
        'user.mfaSecret',
      ]);
    }

    return query.getOne();
  }

  // ==========================================================================
  // Find By Username
  // ==========================================================================

  async findByUsername(
    username: string,
  ): Promise<UserEntity | null> {
    return this.findOne({
      where: {
        username,
        isDeleted: false,
      },
    });
  }

  // ==========================================================================
  // Check Email Exists
  // ==========================================================================

  async existsByEmail(
    email: string,
  ): Promise<boolean> {
    const count = await this.count({
      where: {
        email: email.toLowerCase(),
        isDeleted: false,
      },
    });

    return count > 0;
  }

  // ==========================================================================
  // Check Username Exists
  // ==========================================================================

  async existsByUsername(
    username: string,
  ): Promise<boolean> {
    const count = await this.count({
      where: {
        username,
        isDeleted: false,
      },
    });

    return count > 0;
  }

  // ==========================================================================
  // Create User
  // ==========================================================================

  async createUser(
    payload: Partial<UserEntity>,
  ): Promise<UserEntity> {
    const user = this.create(payload);

    return this.save(user);
  }

  // ==========================================================================
  // Update User
  // ==========================================================================

  async updateUser(
    id: string,
    payload: Partial<UserEntity>,
  ): Promise<UserEntity> {
    const user = await this.findById(id);

    Object.assign(user, payload);

    return this.save(user);
  }

  // ==========================================================================
  // Soft Delete User
  // ==========================================================================

  async softDeleteUser(
    id: string,
  ): Promise<void> {
    const user = await this.findById(id);

    user.isDeleted = true;
    user.isActive = false;

    await this.save(user);
  }

  // ==========================================================================
  // Update Login Metadata
  // ==========================================================================

  async updateLoginMetadata(
    userId: string,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    await this.update(userId, {
      lastLoginAt: new Date(),
      lastLoginIp: ip,
      lastUserAgent: userAgent,
      failedLoginAttempts: 0,
    });
  }

  // ==========================================================================
  // Increment Failed Login Attempts
  // ==========================================================================

  async incrementFailedAttempts(
    userId: string,
  ): Promise<void> {
    const user = await this.findById(userId);

    await this.update(userId, {
      failedLoginAttempts:
        user.failedLoginAttempts + 1,
    });
  }

  // ==========================================================================
  // Lock User
  // ==========================================================================

  async lockUser(
    userId: string,
    durationMinutes = 30,
  ): Promise<void> {
    const lockUntil = new Date(
      Date.now() +
        durationMinutes * 60 * 1000,
    );

    await this.update(userId, {
      isLocked: true,
      lockedUntil: lockUntil,
    });
  }

  // ==========================================================================
  // Unlock User
  // ==========================================================================

  async unlockUser(
    userId: string,
  ): Promise<void> {
    await this.update(userId, {
      isLocked: false,
      lockedUntil: null,
      failedLoginAttempts: 0,
    });
  }

  // ==========================================================================
  // Store Refresh Token
  // ==========================================================================

  async updateRefreshToken(
    userId: string,
    hashedToken: string | null,
  ): Promise<void> {
    await this.update(userId, {
      currentHashedRefreshToken:
        hashedToken,
    });
  }

  // ==========================================================================
  // Find Active Users
  // ==========================================================================

  async findActiveUsers(): Promise<UserEntity[]> {
    return this.find({
      where: {
        isActive: true,
        isDeleted: false,
      },

      order: {
        createdAt: 'DESC',
      },
    });
  }

  // ==========================================================================
  // Find Locked Users
  // ==========================================================================

  async findLockedUsers(): Promise<UserEntity[]> {
    return this.find({
      where: {
        isLocked: true,
        isDeleted: false,
      },
    });
  }

  // ==========================================================================
  // Cleanup Expired Locks
  // ==========================================================================

  async cleanupExpiredLocks(): Promise<void> {
    await this.createQueryBuilder()
      .update(UserEntity)
      .set({
        isLocked: false,
        lockedUntil: null,
      })
      .where('lockedUntil < :now', {
        now: new Date(),
      })
      .execute();
  }
}
