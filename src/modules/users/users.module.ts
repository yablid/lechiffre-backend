// src/modules/users/users.module.ts
import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { DatabaseModule } from '../../database/database.module';
import { JwtModule } from '@nestjs/jwt';
import { RolesGuard } from '../../guards/roles.guard';

@Module({
  imports: [
    JwtModule
  ],
  controllers: [UsersController],
  providers: [
    UsersService,
    RolesGuard
  ],
  exports: [UsersService],
})
export class UsersModule {}
