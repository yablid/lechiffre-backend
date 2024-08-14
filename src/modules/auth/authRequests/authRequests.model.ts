// src/modules/auth/authRequests/authRequests.model.ts

class AuthRequest {
  id: string;
  client_id: string;
  redirect_url: string;
  code_challenge: string;
  code_challenge_method: string;
  oauth_state: string;
  user_id?: string;
  auth_code?: string | null;
  created_at?: Date;
  expires_at?: Date;

  constructor(data: Partial<AuthRequest>) {
    Object.assign(this, data);
  }
}

export default AuthRequest;