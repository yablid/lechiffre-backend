// src/modules/auth/authRequests/authRequests.module.ts
import { Module } from '@nestjs/common';
import { AuthRequestsService } from './authRequests.service';
import { DatabaseModule } from "../../../database/database.module";
import { DatabaseService } from '../../../database/database.service';

@Module({
  imports: [ DatabaseModule ],
  providers: [AuthRequestsService, DatabaseService],
  exports: [AuthRequestsService],
})
export class AuthRequestsModule {}
