import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { BackendGuard } from './guards/backend.guard';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { DatabaseModule } from './database/database.module';
import { ConfigModule } from '@nestjs/config';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { ProjectModule } from './modules/project/project.module';
import { CommonModule } from './common/common.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true
    }),
    CommonModule,
    DatabaseModule,
    UsersModule,
    AuthModule,
    ProjectModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: BackendGuard,
    }
  ],
})
export class AppModule {}
