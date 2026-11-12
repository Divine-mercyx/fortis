export default async function routes(app) {
  app.post('/login', async (request) => { // @hit
    return auth.login(request.body);
  });
  app.post('/verify-otp', async (request) => { // @hit
    return auth.verifyOtp(request.body);
  });
  app.post('/accounts', async (request) => accounts.open(request.body));
}
