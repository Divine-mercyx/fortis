// A bank-link popup: the OAuth state and PKCE verifier are one-time values, not credentials.
export async function startBankLink(authUrl: string, state: string, verifier: string) {
  localStorage.setItem('enablebanking_auth_state', state);
  sessionStorage.setItem('auth_code_verifier', verifier);
  localStorage.setItem('auth_redirect', window.location.pathname);
  localStorage.setItem('oauth_nonce', crypto.randomUUID());
  window.open(authUrl, 'bank-auth');
}

export function saveSession(session: { accessToken: string }) {
  localStorage.setItem('auth_token', session.accessToken); // @hit
  localStorage.setItem('session', JSON.stringify(session)); // @hit
}
