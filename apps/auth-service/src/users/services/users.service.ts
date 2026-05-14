// apps/auth-service/src/users/services/users.service.ts

import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';

import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';

import { UserEntity } from '../entities/user.entity';

import { UserRepository } from '../repositories/user.repository';

import { PasswordService } from '../../auth/services/password.service';
import { SessionService } from '../../auth/services/session.service';

@Injectable()
export class UsersService {
  constructor(
    private readonly userRepository: UserRepository,

    private readonly passwordService: PasswordService,

    private readonly sessionService: SessionService,
  ) {}

  // ==========================================================================
  // Create User
  // ==========================================================================

  async createUser(
    dto: CreateUserDto,
  ): Promise<UserEntity> {
    // ------------------------------------------------------------------------
    // Check Existing Email
    // ------------------------------------------------------------------------

    const emailExists =
      await this.userRepository.existsByEmail(
        dto.email,
      );

    if (emailExists) {
      throw new ConflictException(
        'Email already exists',
      );
    }

    // ------------------------------------------------------------------------
    // Check Existing Username
    // ------------------------------------------------------------------------

    const usernameExists =
      await this.userRepository.existsByUsername(
        dto.username,
      );

    if (usernameExists) {
      throw new ConflictException(
        'Username already exists',
      );
    }

    // ------------------------------------------------------------------------
    // Hash Password
    // ------------------------------------------------------------------------

    const hashedPassword =
      await this.passwordService.hashPassword(
        dto.password,
      );

    // ------------------------------------------------------------------------
    // Create User
    // ------------------------------------------------------------------------

    const user =
      await this.userRepository.createUser({
        username: dto.username,
        email: dto.email,
        password: hashedPassword,

        displayName: dto.displayName,

        phoneNumber: dto.phoneNumber,

        avatarUrl: dto.avatarUrl,

        roles: dto.roles || ['user'],
      });

    return user;
  }

  // ==========================================================================
  // Find All Users
  // ==========================================================================

  async findAllUsers(): Promise<UserEntity[]> {
    return this.userRepository.find({
      where: {
        isDeleted: false,
      },

      order: {
        createdAt: 'DESC',
      },
    });
  }

  // ==========================================================================
  // Find User By ID
  // ==========================================================================

  async findUserById(
    id: string,
  ): Promise<UserEntity> {
    return this.userRepository.findById(id);
  }

  // ==========================================================================
  // Find User By Email
  // ==========================================================================

  async findUserByEmail(
    email: string,
  ): Promise<UserEntity | null> {
    return this.userRepository.findByEmail(
      email,
    );
  }

  // ==========================================================================
  // Update User
  // ==========================================================================

  async updateUser(
    id: string,
    dto: UpdateUserDto,
  ): Promise<UserEntity> {
    const user =
      await this.userRepository.findById(id);

    // ------------------------------------------------------------------------
    // Check Email Conflict
    // ------------------------------------------------------------------------

    if (
      dto.email &&
      dto.email !== user.email
    ) {
      const exists =
        await this.userRepository.existsByEmail(
          dto.email,
        );

      if (exists) {
        throw new ConflictException(
          'Email already exists',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Check Username Conflict
    // ------------------------------------------------------------------------

    if (
      dto.username &&
      dto.username !== user.username
    ) {
      const exists =
        await this.userRepository.existsByUsername(
          dto.username,
        );

      if (exists) {
        throw new ConflictException(
          'Username already exists',
        );
      }
    }

    // ------------------------------------------------------------------------
    // Hash Password If Updated
    // ------------------------------------------------------------------------

    if (dto.password) {
      dto.password =
        await this.passwordService.hashPassword(
          dto.password,
        );
    }

    // ------------------------------------------------------------------------
    // Update User
    // ------------------------------------------------------------------------

    return this.userRepository.updateUser(
      id,
      dto,
    );
  }

  // ==========================================================================
  // Delete User
  // ==========================================================================

  async deleteUser(
    id: string,
  ): Promise<{
    success: boolean;
    message: string;
  }> {
    await this.userRepository.softDeleteUser(
      id,
    );

    // Revoke Sessions
    await this.sessionService.revokeAllSessions(
      id,
    );

    return {
      success: true,
      message:
        'User deleted successfully',
    };
  }

  // ==========================================================================
  // Lock User
  // ==========================================================================

  async lockUser(
    id: string,
  ): Promise<{
    success: boolean;
    message: string;
  }> {
    const user =
      await this.userRepository.findById(id);

    if (user.isLocked) {
      throw new BadRequestException(
        'User already locked',
      );
    }

    await this.userRepository.lockUser(id);

    // Revoke active sessions
    await this.sessionService.revokeAllSessions(
      id,
    );

    return {
      success: true,
      message:
        'User account locked successfully',
    };
  }

  // ==========================================================================
  // Unlock User
  // ==========================================================================

  async unlockUser(
    id: string,
  ): Promise<{
    success: boolean;
    message: string;
  }> {
    const user =
      await this.userRepository.findById(id);

    if (!user.isLocked) {
      throw new BadRequestException(
        'User is not locked',
      );
    }

    await this.userRepository.unlockUser(id);

    return {
      success: true,
      message:
        'User account unlocked successfully',
    };
  }

  // ==========================================================================
  // Get User Sessions
  // ==========================================================================

  async getUserSessions(
    userId: string,
  ) {
    return this.sessionService.getUserSessions(
      userId,
    );
  }

  // ==========================================================================
  // Revoke User Sessions
  // ==========================================================================

  async revokeUserSessions(
    userId: string,
  ): Promise<{
    success: boolean;
    message: string;
  }> {
    await this.userRepository.findById(userId);

    await this.sessionService.revokeAllSessions(
      userId,
    );

    return {
      success: true,
      message:
        'All user sessions revoked',
    };
  }

  // ==========================================================================
  // Activate User
  // ==========================================================================

  async activateUser(
    userId: string,
  ): Promise<UserEntity> {
    return this.userRepository.updateUser(
      userId,
      {
        isActive: true,
      },
    );
  }

  // ==========================================================================
  // Deactivate User
  // ==========================================================================

  async deactivateUser(
    userId: string,
  ): Promise<UserEntity> {
    await this.sessionService.revokeAllSessions(
      userId,
    );

    return this.userRepository.updateUser(
      userId,
      {
        isActive: false,
      },
    );
  }

  // ==========================================================================
  // Verify Email
  // ==========================================================================

  async verifyEmail(
    userId: string,
  ): Promise<UserEntity> {
    return this.userRepository.updateUser(
      userId,
      {
        isEmailVerified: true,
      },
    );
  }

  // ==========================================================================
  // Change Password
  // ==========================================================================

  async changePassword(
    userId: string,
    newPassword: string,
  ): Promise<void> {
    const hashedPassword =
      await this.passwordService.hashPassword(
        newPassword,
      );

    await this.userRepository.updateUser(
      userId,
      {
        password: hashedPassword,
      },
    );

    // Revoke all existing sessions
    await this.sessionService.revokeAllSessions(
      userId,
    );
  }

  // ==========================================================================
  // Get Active Users
  // ==========================================================================

  async getActiveUsers(): Promise<UserEntity[]> {
    return this.userRepository.findActiveUsers();
  }

  // ==========================================================================
  // Get Locked Users
  // ==========================================================================

  async getLockedUsers(): Promise<UserEntity[]> {
    return this.userRepository.findLockedUsers();
  }

  // ==========================================================================
  // Cleanup Expired Locks
  // ==========================================================================

  async cleanupExpiredLocks(): Promise<void> {
    await this.userRepository.cleanupExpiredLocks();
  }
}
