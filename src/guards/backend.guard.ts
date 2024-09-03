// src/guards/backend.guard.ts
/* general api key guard */
import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class BackendGuard implements CanActivate {
  private readonly apiKey: string;

  constructor(
    private readonly configService: ConfigService,
  ) {
    this.apiKey = this.configService.get<string>('BACKEND_API_KEY');
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const apiKey = request.headers['x-api-key'];

    if (apiKey !== this.apiKey) {
      throw new UnauthorizedException('Invalid API key');
    }

    return true;
  }
}
