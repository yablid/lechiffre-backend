// src/modules/auth/authRequests/authRequests.service.ts
import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { DatabaseService } from '../../../database/database.service';
import AuthRequest from './authRequests.model';

@Injectable()
export class AuthRequestsService {
  constructor(private readonly databaseService: DatabaseService) {}

  async storeAuthRequest(authRequest: AuthRequest): Promise<void> {
    const query = `
      INSERT INTO auth_requests (id, client_id, redirect_uri, code_challenge, code_challenge_method, oauth_state, created_at, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + INTERVAL '10 minutes')
    `;
    const params = [
      authRequest.id,
      authRequest.clientId,
      authRequest.redirectUri,
      authRequest.codeChallenge,
      authRequest.codeChallengeMethod,
      authRequest.oauthState,
    ];
    try {
      await this.databaseService.query(query, params);
      console.log("Saved auth request to database");
    } catch (error) {
      console.error('Error saving auth request to database:', error);
      throw new InternalServerErrorException("Error saving auth request to database");
    }
  }

  async findById(tempId: string): Promise<AuthRequest> {
    const query = `
      SELECT * FROM auth_requests WHERE id = $1 AND expires_at > NOW()
    `;
    const result = await this.databaseService.query(query, [tempId]);
    return result.rows[0];
  }


  async storeAuthCode(authCode: string, authRequest: AuthRequest): Promise<void> {
    const query = `
      UPDATE auth_requests
      SET auth_code = $1
      WHERE id = $2
    `;
    const params = [authCode, authRequest.id];
    await this.databaseService.query(query, params);
  }

  async storeUserId(authRequestId: string, userId: string): Promise<void> {
    const query = `
      UPDATE auth_requests
      SET user_id = $1
      WHERE id = $2
    `;
    await this.databaseService.query(query, [userId, authRequestId]);
  }

  async findByAuthCode(authCode: string): Promise<AuthRequest | null> {
  const query = `
    SELECT * FROM auth_requests WHERE auth_code = $1 AND expires_at > NOW()
  `;
  const result = await this.databaseService.query(query, [authCode]);

  if (result.rows.length > 0) {
    const row = result.rows[0];
    return new AuthRequest(
      row.id,
      row.client_id,
      row.redirect_uri,
      row.code_challenge,
      row.code_challenge_method,
      row.user_id,
      row.auth_code,
      row.created_at,
      row.expires_at
    );
  }
  return null; // Return null if no matching request is found
}

  async deleteAuthRequest(auth_request_id: string): Promise<void> {
    const query = `
      DELETE FROM auth_requests WHERE id = $1
    `;
    await this.databaseService.query(query, [auth_request_id]);
  }

  async clearAuthCode(authRequestId: string): Promise<void> {
    const query = `
        UPDATE auth_requests
        SET auth_code  = NULL,
            expires_at = NULL
        WHERE id = $1
    `;
    await this.databaseService.query(query, [authRequestId]);
  }
}
