// src/guards/access.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { TokenExpiredError, JsonWebTokenError } from '@nestjs/jwt';
import { Request } from 'express';
import { AuthService } from '../modules/auth/auth.service'
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AccessGuard implements CanActivate {
  private readonly JWT_SECRET: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    this.JWT_SECRET = configService.get<string>('JWT_SECRET');
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const accessToken = this.authService.extractTokenFromHeader(request);

    if (!accessToken) {
      throw new UnauthorizedException('Access token missing');
    }

    try {
      // Verify the access token
      const payload = this.authService.verifyAccessToken(accessToken);

      // Attach the user to the request object
      request.user = { id: payload.sub, role_id: payload.role_id }
      return true;
    } catch (error) {
        if (error instanceof TokenExpiredError) {
          throw new UnauthorizedException('AccessTokenExpired')
        } else if (error instanceof JsonWebTokenError) {
          throw new UnauthorizedException('InvalidAccessToken')
        } else {
          console.error('Access token invalid or expired:', error);
          throw new UnauthorizedException('Unauthorized');
        }
    }
  }
}
