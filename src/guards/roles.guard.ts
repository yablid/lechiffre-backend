// src/guards/roles.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import {JsonWebTokenError, TokenExpiredError} from "@nestjs/jwt";

@Injectable()
export class RolesGuard implements CanActivate {
  private readonly JWT_SECRET: string;

  constructor(
    private reflector: Reflector,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {
    this.JWT_SECRET = configService.get<string>('JWT_SECRET');
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>()
    const accessToken = request.headers['authorization']?.split(' ')[1];

    if (!accessToken) {
      throw new UnauthorizedException('Access token missing');
    }

    try {
      // Verify the access token
      const payload = this.jwtService.verify(accessToken, { secret: this.JWT_SECRET });
      request.user = {id: payload.sub, role_id: payload.role_id}

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

    const requiredRole = this.reflector.get<number>('role_id', context.getHandler()) ||
                        this.reflector.get<number>('role_id', context.getClass());

    if (requiredRole === undefined) {
      // If no role was provided in controller guard code, deny
      throw new ForbiddenException('Role not defined');
    }

    if (request.user.role_id > requiredRole) {
      throw new ForbiddenException('User does not have the required role');
    }

    return true;
  }
}
