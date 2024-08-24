
# Auth0 - Proof Key for Code Exchange (PKCE)
(pkce)

```src/components/initAuth```

 1. Generate ```code_verifier``` and ```code_challenge```
 2. Store ```code_verifier```, ```oauth_state``` in sessionStorage
 3. Send GET request to backend ```auth/authorize``` with:
    - ```client_id```
    - ```redirect_address``` (on success)
    - ```code_challenge```
    - ```code_challenge_method```
    - ```oauth_state```

```Backend```

 1. Store ```auth_request``` in db
 2. Return redirect to login with ```auth_request_id``` as url parameter.

```Login```

 1. User enters ```username```, ```password```
 2. user/pass -> backend along with ```auth_request_id```

```Backend```

 1. Validate password against username
 2. [add user_id to ```auth_request``` in db]
 3. Generate ```auth_code``` (uuidv4), store in db ```auth_request
 4. Vet original auth_request ```redirect_url``` against allowed urls
 5. Return ```redirect_url``` (/token) with ```auth_code``` and ```oauth_state``` (from db ```auth_request```)

```TokenExchange```

 1. Compare url param ```oauth_state``` with sessionStorage ```oauth_state```
 2. POST url param ```code``` and sessionStorage ```code_verifier``` to backend ```auth/exchange-tokens```

```Backend```

 1. Find ```auth_request``` by using ```code```
 2. Verify ```auth_request``` ```code_challenge``` against ```code_verifier```
 3. [Find user info, e.g. via ```user_id``` in ```auth_request```]
 4. Generate ```access_token```, ```id_token```, ```refresh_token```
 5. Store ```refreshToken``` in httpOnly cookie
 6. Return ```access_token``` and ```id_token```