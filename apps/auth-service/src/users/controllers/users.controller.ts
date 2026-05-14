// apps/auth-service/src/users/controllers/users.controller.ts

import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';

import { UsersService } from '../services/users.service';

import { CreateUserDto } from '../dto/create-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';

import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';

import { Roles } from '../../auth/decorators/roles.decorator';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
  ) {}

  // ==========================================================================
  // Create User
  // ==========================================================================

  @Post()
  @Roles('admin')
  @HttpCode(HttpStatus.CREATED)
  async createUser(
    @Body() dto: CreateUserDto,
  ) {
    return this.usersService.createUser(dto);
  }

  // ==========================================================================
  // Get All Users
  // ==========================================================================

  @Get()
  @Roles('admin')
  async getAllUsers() {
    return this.usersService.findAllUsers();
  }

  // ==========================================================================
  // Get User By ID
  // ==========================================================================

  @Get(':id')
  @Roles('admin', 'moderator')
  async getUserById(
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.usersService.findUserById(id);
  }

  // ==========================================================================
  // Update User
  // ==========================================================================

  @Patch(':id')
  @Roles('admin')
  async updateUser(
    @Param('id', new ParseUUIDPipe()) id: string,

    @Body() dto: UpdateUserDto,
  ) {
    return this.usersService.updateUser(id, dto);
  }

  // ==========================================================================
  // Delete User
  // ==========================================================================

  @Delete(':id')
  @Roles('admin')
  @HttpCode(HttpStatus.OK)
  async deleteUser(
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.usersService.deleteUser(id);
  }

  // ==========================================================================
  // Get User Sessions
  // ==========================================================================

  @Get(':id/sessions')
  @Roles('admin')
  async getUserSessions(
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.usersService.getUserSessions(id);
  }

  // ==========================================================================
  // Revoke User Sessions
  // ==========================================================================

  @Delete(':id/sessions')
  @Roles('admin')
  async revokeUserSessions(
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.usersService.revokeUserSessions(id);
  }

  // ==========================================================================
  // Lock User Account
  // ==========================================================================

  @Patch(':id/lock')
  @Roles('admin')
  async lockUser(
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.usersService.lockUser(id);
  }

  // ==========================================================================
  // Unlock User Account
  // ==========================================================================

  @Patch(':id/unlock')
  @Roles('admin')
  async unlockUser(
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.usersService.unlockUser(id);
  }
}
