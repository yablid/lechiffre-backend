/* src/sql/create_auth_requests_table.sql */
CREATE TABLE IF NOT EXISTS auth_requests (
    id UUID PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    redirect_url TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method VARCHAR(255),
    oauth_state TEXT,
    user_id UUID,  -- Optional, can be null initially, and populated after login
    auth_code TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP + INTERVAL '5 minutes'  -- Optional, auto-expire after some time
);
