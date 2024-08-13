// src/modules/auth/authRequests/authRequests.model.ts

class AuthRequest {
  id: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  oauthState: string;
  userId?: string;
  authCode?: string | null;
  createdAt?: Date;
  expiresAt?: Date;

  constructor(
    id: string,
    clientId: string,
    redirectUri: string,
    codeChallenge: string,
    codeChallengeMethod: string,
    oauthState: string | null = null,
    userId: string | null = null,
    authCode: string | null = null,
    createdAt?: Date | null,
    expiresAt?: Date | null
  ) {
    this.id = id;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.codeChallenge = codeChallenge;
    this.codeChallengeMethod = codeChallengeMethod;
    this.oauthState = oauthState;
    this.userId = userId;
    this.authCode = authCode;
    this.createdAt = createdAt;
    this.expiresAt = expiresAt;
  }
}

export default AuthRequest;