// src/modules/auth/auth.controller.ts
import { v4 as uuidv4 } from 'uuid';
import {Controller, Post, Get, Res, Req, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { AuthRequestsService } from './authRequests/authRequests.service';
import { ConfigService } from "@nestjs/config";
import { Request, Response } from 'express';
import { IUser } from './auth.service';


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
  async verifyAccessToken(@Req() req: Request): Promise<IUser> {
    const token = req.headers['authorization']?.split(' ')[1]; // Extract the Bearer token
    if (!token || token==='null') {
      console.log("auth.controller found no access token.")
      throw new UnauthorizedException('Access token not provided');
    }
    console.log("auth.controller verifying access token...");
    try {
      return this.authService.verifyAccessToken(token);
    } catch (error) {
      console.log("Access token is invalid or expired.")
      throw new UnauthorizedException('Access token is invalid or expired');
    }
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
    const { client_id, redirect_url, code_challenge, code_challenge_method, oauth_state } = req.query;

    // Only using login/pass for now but any initial/additional auth could happen here
    // const user = await this.AuthService.otherAuthenticationMethods(req);
    const user = false;

    if (!user) {
      const authRequestId = uuidv4();
      const authRequest = {
        id: authRequestId,
        client_id: client_id as string,
        redirect_url: redirect_url as string,
        code_challenge: code_challenge as string,
        code_challenge_method: code_challenge_method as string,
        oauth_state: oauth_state as string,
      }

      await this.authRequestsService.storeAuthRequest(authRequest)

      // todo: Fix for production
      console.log("Server returning login endpoint for redirect...");
      const redirectPath = `/login?auth_request_id=${authRequestId}`;
      return res.status(200).send({ redirectPath });
    }
  }

  @Post('login')
  async login(@Req() req: Request, @Res() res: Response) {
    console.log("auth.controller login called with req.body: ", req.body);
    const { email, password, auth_request_id } = req.body;

    const user = await this.authService.validateUser(email, password);
    if (!user) {
      console.log(`auth.controller unable to validate user: ${email}`);
      return res.status(401).send({ message: 'Invalid email or password' });
    }
    console.log(`auth.controller validated user: ${email} user.id: ${user.id}`);

    const authRequest = await this.authRequestsService.findById(auth_request_id);
    if (!authRequest) {
      return res.status(400).send({ message: 'Invalid authentication request' });
    }

    await this.authRequestsService.storeUserId(auth_request_id, user.id);

    const auth_code = uuidv4()
    const oauth_state = authRequest.oauth_state;
    console.log("auth.controller token exchange oauth_state: ", oauth_state)
    await this.authRequestsService.storeAuthCode(auth_code, authRequest);

    console.log("auth.controller login auth_request object:", authRequest);

    const redirectUrl = `${authRequest.redirect_url}?code=${auth_code}&oauth_state=${oauth_state}`;

    if (!this.allowedRedirectUris.includes(authRequest.redirect_url)) {
      console.error(
        "ERROR: Someone may be messing with your redirect URI. Expected: ", this.allowedRedirectUris,
        "Received: ", authRequest.redirect_url
      );
      return res.status(400).send({message: 'Invalid redirect URI'});
    }
    return res.status(200).send({ redirectUrl });
  }

  @Post('exchange-tokens')
  async exchangeTokens(@Req() req: Request, @Res() res: Response) {
    console.log("auth.controller running token exchange...");
    const { code, code_verifier } = req.body;

    if (!code || !code_verifier) {
      console.error("Missing authorization code or code verifier");
      throw new UnauthorizedException('Missing authorization information.');
    }

    const authRequest = await this.authRequestsService.findByAuthCode(code);
    if (!authRequest) {
      return res.status(400).send({ message: 'Invalid or expired authorization code' });
    }
    console.log("auth.controller exchanging tokens for auth request:", authRequest);


    console.log("Verifying code verifier...")
    const isValidVerifier = this.authService.verifyCodeVerifier(
      authRequest.code_challenge,
      code_verifier,
      authRequest.code_challenge_method
    );

    if (!isValidVerifier) {
      throw new UnauthorizedException('Challenge unsuccessful.');
    }
    console.log(`Verifier verified. Fetching user/roles for: ${authRequest.user_id} `)
    const user = await this.usersService.findById(authRequest.user_id);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    console.log("auth.controller token exchange generating new tokens...")
    const accessToken = this.authService.generateAccessToken(authRequest.user_id, user.role_id );
    const refreshToken = this.authService.generateRefreshToken(authRequest.user_id);
    const idToken = this.authService.generateIdToken(authRequest.user_id, user.email);

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
