// src/modules/auth/auth.controller.ts
import { v4 as uuidv4 } from 'uuid';
import {Controller, Post, Get, Res, Req, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { AuthRequestsService } from './authRequests/authRequests.service';
import { ConfigService } from "@nestjs/config";
import { Request, Response } from 'express';


@Controller('auth')
export class AuthController {
  private readonly allowedRedirectUris: string[];
  private readonly nodeEnv: string;

  constructor(
    private authService: AuthService,
    private readonly usersService: UsersService,
    private readonly authRequestsService: AuthRequestsService,
    private readonly configService: ConfigService,
  ) {
    this.allowedRedirectUris = this.configService.get<string>('ALLOWED_REDIRECT_URIS').split(',');
    this.nodeEnv = this.configService.get<string>('NODE_ENV');
  }

  @Get('access-token')
  async verifyAccessToken(@Req() req: Request) {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract the Bearer token
    if (!token) {
      throw new UnauthorizedException('Access token not provided');
    }
    console.log("auth.controller verifying access token...");
    const isValid = await this.authService.verifyAccessToken(token);
    if (!isValid) {
      throw new UnauthorizedException('Access token is invalid or expired');
    }
    return { valid: true };
  }

  @Post('refresh-token')
  async refreshToken(@Req() req: Request, @Res() res: Response) {
    console.log("auth.controller refreshToken called");
    const refreshToken = req.cookies['refresh-token']
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token found');
    }
    const result = await this.authService.refreshAccessToken(refreshToken);
    res.send(result);
  }

  @Get('authorize')
  async authorize(@Req() req: Request, @Res() res: Response) {
    console.log("Authorize called. Initiating backend PKCE flow...");
    const { client_id, redirect_uri, code_challenge, code_challenge_method, oauth_state } = req.query;

    // Only using login/pass for now but any initial/additional auth could happen here
    // const user = await this.AuthService.otherAuthenticationMethods(req);
    const user = false;

    if (!user) {
      const authRequestId = uuidv4();
      const authRequest = {
        id: authRequestId,
        clientId: client_id as string,
        redirectUri: redirect_uri as string,
        codeChallenge: code_challenge as string,
        codeChallengeMethod: code_challenge_method as string,
        oauthState: oauth_state as string,
      }

      await this.authRequestsService.storeAuthRequest(authRequest)

      // todo: Fix for production
      console.log("Server returning login endpoint for redirect...");
      const redirectUrl = `/login?auth_request_id=${authRequestId}`;
      return res.json({ redirectUrl });
    }
  }

  @Post('login')
  async login(@Req() req: Request, @Res() res: Response) {
    const { username, password, auth_request_id } = req.body;

    const user = await this.authService.validateUser(username, password);
    if (!user) {
      return res.status(401).send({ message: 'Invalid username or password' });
    }

    const authRequest = await this.authRequestsService.findById(auth_request_id);
    if (!authRequest) {
      return res.status(400).send({ message: 'Invalid authentication request' });
    }

    await this.authRequestsService.storeUserId(auth_request_id, user.id);

    const authCode = uuidv4()
    const oauthState = authRequest.oauthState;

    await this.authRequestsService.storeAuthCode(authCode, authRequest);

    const redirectUri = `${authRequest.redirectUri}?code=${authCode}&oauth_state=${oauthState}`;

    if (!this.allowedRedirectUris.includes(authRequest.redirectUri)) {
      console.error(
        "ERROR: Someone may be messing with your redirect URI. Expected: ", this.allowedRedirectUris,
        "Received: ", authRequest.redirectUri
      );
      return res.status(400).send({message: 'Invalid redirect URI'});
    }

    return res.redirect(redirectUri);
  }

  @Post('exchange-tokens')
  async exchangeToken(@Req() req: Request, @Res() res: Response) {
    const { code, code_verifier } = req.body;

    if (!code || !code_verifier) {
      console.error("Missing authorization code or code verifier");
      throw new UnauthorizedException('Missing authorization information.');
    }

    const authRequest = await this.authRequestsService.findByAuthCode(code);
    if (!authRequest) {
      return res.status(400).send({ message: 'Invalid or expired authorization code' });
    }

    const isValidVerifier = this.authService.verifyCodeVerifier(
      authRequest.codeChallenge,
      code_verifier,
      authRequest.codeChallengeMethod
    );
    if (!isValidVerifier) {
      throw new UnauthorizedException('Challenge unsuccessful.');
    }

    const user = await this.usersService.findById(authRequest.userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    const roles = await this.usersService.getUserRoles(user.id);
    const roleIds = roles.map(role => role.role_id);

    const accessToken = this.authService.generateAccessToken(authRequest.userId, roleIds );
    const refreshToken = this.authService.generateRefreshToken(authRequest.userId);
    const idToken = this.authService.generateIdToken(authRequest.userId, user.username);

    res.cookie('refresh-token', refreshToken, {
      httpOnly: true,
      secure: this.nodeEnv != 'development',  // Set to true if using HTTPS
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 * 24 * 7,  // 7 days
    });
    console.log("Deleting auth request - token exchange successful.")
    await this.authRequestsService.deleteAuthRequest(authRequest.id);

    return res.status(200).send({
      accessToken,
      idToken,
    });
  }

  @Get('identify')
  async identify(@Req() req: Request, @Res() res: Response) {
    const accessToken = this.authService.extractTokenFromHeader(req);

    if (!accessToken) {
      throw new UnauthorizedException('Access token missing');
    }

    try {
      const { idToken } = await this.authService.identify(accessToken);
      return res.status(201).send({ idToken });
    } catch (error) {
      console.error('Identify error:', error);
      throw new UnauthorizedException('Unable to identify user');
    }
  }
}
