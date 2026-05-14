// apps/auth-service/src/users/dto/update-user.dto.ts

import {
  IsEmail,
  IsOptional,
  IsString,
  IsStrongPassword,
  IsArray,
  ArrayNotEmpty,
  MinLength,
  MaxLength,
  Matches,
  IsBoolean,
} from 'class-validator';

export class UpdateUserDto {
  // ==========================================================================
  // Username
  // ==========================================================================

  @IsOptional()
  @IsString()

  @MinLength(4)
  @MaxLength(32)

  @Matches(/^[a-zA-Z0-9_.-]+$/, {
    message:
      'Username may only contain letters, numbers, underscores, dots and hyphens',
  })
  username?: string;

  // ==========================================================================
  // Email
  // ==========================================================================

  @IsOptional()
  @IsEmail()

  @MaxLength(120)
  email?: string;

  // ==========================================================================
  // Password
  // ==========================================================================

  @IsOptional()
  @IsStrongPassword(
    {
      minLength: 10,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    },
    {
      message:
        'Password must contain uppercase, lowercase, number and special character',
    },
  )
  password?: string;

  // ==========================================================================
  // Display Name
  // ==========================================================================

  @IsOptional()
  @IsString()

  @MinLength(2)
  @MaxLength(64)
  displayName?: string;

  // ==========================================================================
  // Roles
  // ==========================================================================

  @IsOptional()
  @IsArray()

  @ArrayNotEmpty()
  @IsString({ each: true })
  roles?: string[];

  // ==========================================================================
  // Phone Number
  // ==========================================================================

  @IsOptional()
  @Matches(/^\+?[0-9]{8,15}$/, {
    message: 'Invalid phone number format',
  })
  phoneNumber?: string;

  // ==========================================================================
  // Avatar URL
  // ==========================================================================

  @IsOptional()
  @IsString()
  avatarUrl?: string;

  // ==========================================================================
  // Account Status
  // ==========================================================================

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  // ==========================================================================
  // Account Lock Status
  // ==========================================================================

  @IsOptional()
  @IsBoolean()
  isLocked?: boolean;

  // ==========================================================================
  // Email Verification
  // ==========================================================================

  @IsOptional()
  @IsBoolean()
  isEmailVerified?: boolean;
}
