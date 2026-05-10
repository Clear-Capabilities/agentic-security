import crypto from 'crypto';

export function buildAuthorizeUrl(state) {
  const code_verifier = crypto.randomBytes(64).toString('base64url');
  const code_challenge = crypto.createHash('sha256').update(code_verifier).digest('base64url');
  const params = new URLSearchParams({
    client_id: process.env.OAUTH_CLIENT_ID,
    response_type: 'code',
    state,
    redirect_uri: 'https://app.example/callback',
    code_challenge,
    code_challenge_method: 'S256',
  });
  return 'https://auth.example/authorize?' + params.toString();
}
