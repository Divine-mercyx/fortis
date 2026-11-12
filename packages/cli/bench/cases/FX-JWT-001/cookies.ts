export function setTokens(res, access: string, refresh: string) {
  res.cookie('access_token', access, { httpOnly: false, secure: true }); // @hit
  res.cookie('refresh_token', refresh, { httpOnly: true, secure: false }); // @hit
  res.cookie('theme', 'dark', { httpOnly: false });
  res.cookie('session_id', access, { httpOnly: true, secure: true, sameSite: 'lax' });
}
