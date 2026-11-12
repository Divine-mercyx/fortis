export class PasswordResetService {
  async requestReset(email: string, req: Request) {
    const user = await this.users.findByEmail(email);
    const token = Date.now().toString(36); // @hit
    const url = `${req.protocol}://${req.get('host')}/reset/${token}`; // @hit
    await this.mail.send(user.email, url);
    return { token };
  }
}
