// src/modules/auth/authRequests/authRequests.module.ts
import { Module } from '@nestjs/common';
import { AuthRequestsService } from './authRequests.service';
import { DatabaseModule } from "../../../database/database.module";

@Module({
  imports: [DatabaseModule],
  providers: [AuthRequestsService],
  exports: [AuthRequestsService],
})
export class AuthRequestsModule {}
