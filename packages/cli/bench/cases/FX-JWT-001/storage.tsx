export function onLogin(token: string, refresh: string) {
  localStorage.setItem('accessToken', token); // @hit
  sessionStorage.setItem('refresh_token', refresh); // @hit
  localStorage.setItem('theme', 'dark');
  localStorage.setItem('lastSeenRelease', '1.4.0');
}
