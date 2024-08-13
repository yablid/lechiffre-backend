// src/modules/auth/auth.service.ts
import {BadRequestException, Injectable, UnauthorizedException} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import User from '../users/users.model';
import { Request, Response } from 'express';
import * as crypto from 'crypto';
import base64url from 'base64url';

interface IUser {
  sub: string;
  roles: number[];
}

@Injectable()
export class AuthService {
  private readonly JWT_SECRET: string;
  private readonly JWT_REFRESH_SECRET: string;

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService
  ) {
    this.JWT_SECRET = this.configService.get<string>('JWT_SECRET');
    this.JWT_REFRESH_SECRET = this.configService.get<string>('JWT_REFRESH_SECRET');
  }

  verifyAccessToken(token: string): IUser {
    console.log("auth.service verifying access token...");
    const secret = this.JWT_SECRET;
    if (!secret) {
      throw new UnauthorizedException('JWT_SECRET not set');
    }
    const payload = this.jwtService.verify(token, { secret: secret });
    return { sub: payload.sub, roles: payload.roles };
  }

  async refreshAccessToken(refreshToken: string) {

    const refreshSecret = this.JWT_REFRESH_SECRET;
    if (!refreshSecret) {
      console.error("Env variable for refresh secret inaccessible.")
      throw new UnauthorizedException('Unable to decode refresh token');
    }
    const payload = this.jwtService.verify(refreshToken, {secret: refreshSecret,});
    console.log("auth.service refreshing access token for user payload: ", payload);

    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException(`Unable to find user: ${payload.sub} in database`);
    }

    const roles = await this.usersService.getUserRoles(user.id);
    const roleIds = roles.map(role => role.role_id);
    const accessToken = this.generateAccessToken(user.id, roleIds);
    const idToken = this.generateIdToken(user.id, user.username);

    return {
      accessToken,
      idToken,
    }
  }

  async validateUser(username: string, pass: string): Promise<Omit<User, "password"> | null> {
    console.log(`auth.service validating user...`);
    const user = await this.usersService.findByUsername(username);
    if (!user) {
      throw new UnauthorizedException(`Username not found`);
    }
    console.log("auth.service validateUser DB user: ", user);
    const verified = await argon2.verify(user.password, pass);

    if (user && verified) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user;
      console.log(`User validated: ${result}`);
      return result;
    }
    console.log(`User not validated: ${username}`);
    return null;
  }

  verifyCodeVerifier(codeChallenge: string, codeVerifier: string, method: string = 'S256'): boolean {
    let derivedChallenge;

    if (method === 'S256') {
      derivedChallenge = base64url(crypto.createHash('sha256').update(codeVerifier).digest());
    } else {
      // If method is not S256, just return the code verifier as is
      derivedChallenge = codeVerifier;
    }

    return derivedChallenge === codeChallenge;
  }

  generateRefreshToken(userId: string): string {
    return this.jwtService.sign({ sub: userId }, {
      secret: this.JWT_REFRESH_SECRET,
      expiresIn: '7d',  // Refresh tokens are longer-lived
    });
  }

  generateAccessToken(userId: string, roles: number[]): string {
    return this.jwtService.sign({ sub: userId, roles: roles }, {
      secret: this.JWT_SECRET,
      expiresIn: '15m',  // Access tokens are usually short-lived
    });
  }

  generateIdToken(userId: string, username: string): string {
    // Typically contains user-specific claims
    const claims = {
      sub: userId,
      username: username
    }
    const jwt_secret = this.JWT_SECRET;
    return this.jwtService.sign(claims, {secret: jwt_secret, expiresIn: '15m'});
  }

  async identify(accessToken: string) {
    const payload = this.jwtService.verify(accessToken, { secret: this.JWT_SECRET });
    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException(`Unable to find user: ${payload.sub} in database`);
    }
    const idToken = this.generateIdToken(user.id, user.username);
    return { idToken };
  }

  extractTokenFromHeader(request: Request): string | null {
    const authHeader = request.headers['authorization'];
    if (!authHeader) {
      return null;
    }
    const [bearer, token] = authHeader.split(' ');
    return bearer === 'Bearer' && token ? token : null;
  }




  async login(user: Omit<User, 'password'>, res: Response) {

    console.log("auth.service generating JWT token");
    const payload = { username: user.username, sub: user.id };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.JWT_SECRET,
      expiresIn: '15m',
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.JWT_REFRESH_SECRET,
      expiresIn: '7d',
    });

    const NODE_ENV = this.configService.get('NODE_ENV');

    res.cookie('refresh-token', refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    })

    return res.send({
      message: 'Login successful',
      accessToken,
      user: {
        username: user.username,
        roles: user.roles,
      }
    })
  }







}
