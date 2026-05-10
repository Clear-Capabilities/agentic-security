export function buildAuthorizeUrl(state) {
  const params = new URLSearchParams({
    client_id: process.env.OAUTH_CLIENT_ID,
    response_type: 'code',
    state,
    redirect_uri: 'https://app.example/callback',
  });
  return 'https://auth.example/authorize?' + params.toString();
}
