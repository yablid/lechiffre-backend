// src/modules/auth/auth.service.ts
import {BadRequestException, Injectable, UnauthorizedException} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RolesService } from '../roles/roles.service';
import * as argon2 from 'argon2';
import User from '../users/schema/users.model';
import { Request, Response } from 'express';
import * as crypto from 'crypto';
import base64url from 'base64url';
import * as path from "path";
import * as fs from "fs";

import { CreateUserDto } from '../users/dto/create-user.dto';

export interface IUser {
  sub: string;
  roles: number[];
}

@Injectable()
export class AuthService {
  private predefinedUsers: CreateUserDto[];
  private readonly JWT_SECRET: string;
  private readonly JWT_REFRESH_SECRET: string;

  constructor(
    private usersService: UsersService,
    private readonly rolesService: RolesService,
    private jwtService: JwtService,
    private configService: ConfigService
  ) {
    this.JWT_SECRET = this.configService.get<string>('JWT_SECRET');
    this.JWT_REFRESH_SECRET = this.configService.get<string>('JWT_REFRESH_SECRET');
    this.loadPredefinedUsers();
  }

  // temp create predefined users
  async onModuleInit() {
    console.log('AuthService onModuleInit - creating predefined users');
    await this.createPredefinedUsers();
  }
  private loadPredefinedUsers() {
    console.log("dirname: ", __dirname)
    const filePath = path.join(__dirname, 'predefinedUsers.json');
    const jsonData = fs.readFileSync(filePath, 'utf8');

    this.predefinedUsers = JSON.parse(jsonData).map((user: { email: string, role_id: number}) => {
      const { email, role_id } = user;
      return { email, role_id } as CreateUserDto;
    });
  }

  async createPredefinedUsers() {
    for (const user of this.predefinedUsers) {
      try {
        const emailExists = await this.usersService.findByEmail(user.email);
        if (emailExists) {
          continue;
        }
      } catch (error) {
        console.log("User not found.")
      }
      await this.rolesService.validateRole(user.role_id); // Ensure the role is valid
      await this.usersService.create(user);
    }
  }

  verifyAccessToken(token: string): IUser {
    console.log(`auth.service verifying access token: ${token}`);
    const secret = this.JWT_SECRET;
    if (!secret) {
      throw new UnauthorizedException('JWT_SECRET not set');
    }
    if (!token) {
      throw new UnauthorizedException('Access token not provided');
    }
    try {
      const payload = this.jwtService.verify(token, { secret: secret });
      console.log("auth.service verifyAccessToken payload: ", payload);
      return { sub: payload.sub, roles: payload.roles };
    } catch (error) {
      console.error('Error verifying access token:', error);
      throw new UnauthorizedException('Invalid access token');
    }
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
    const idToken = this.generateIdToken(user.id, user.email);

    return {
      accessToken,
      idToken,
    }
  }

  async validateUser(email: string, pass: string): Promise<Omit<User, "password"> | null> {

    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new UnauthorizedException(`email not found`);
    }
    const verified = await argon2.verify(user.password, pass);

    if (user && verified) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user;
      console.log(`User validated: ${result}`);
      return result;
    }
    console.log(`User not validated: ${email}`);
    return null;
  }

  verifyCodeVerifier(codeChallenge: string, codeVerifier: string, method: string = 'S256'): boolean {
    let derivedChallenge: string;

    if (method === 'S256') {
      derivedChallenge = base64url(crypto.createHash('sha256').update(codeVerifier).digest());
    } else {
      // If method is not S256, just return the code verifier as is
      derivedChallenge = codeVerifier;
    }
    console.log("Code verification result: ", derivedChallenge === codeChallenge)
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

  generateIdToken(userId: string, email: string): string {
    // Typically contains user-specific claims
    const claims = {
      sub: userId,
      email: email
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
    const idToken = this.generateIdToken(user.id, user.email);
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
    const payload = { email: user.email, sub: user.id };

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
        email: user.email,
        roles: user.roles,
      }
    })
  }







}
