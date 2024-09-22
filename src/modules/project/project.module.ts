// modules/project/project.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { ProjectController } from './project.controller';
import { ProjectService } from './project.service';
import { RolesGuard } from '../../guards/roles.guard';
import { CommonModule } from '../../common/common.module';

@Module({
  imports: [
        JwtModule.register({
          secret: process.env.JWT_SECRET,
          signOptions: { expiresIn: '60s' },
        }),
        ConfigModule,
        CommonModule,
  ],
  controllers: [ProjectController],
  providers: [ ProjectService, RolesGuard ],
})
export class ProjectModule {}
