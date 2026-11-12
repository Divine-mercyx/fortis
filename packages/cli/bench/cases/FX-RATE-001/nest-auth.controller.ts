import { Body, Controller, Post } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  login(@Body() body: LoginDto) {
    return this.auth.login(body);
  }

  @Post('otp/verify') // @hit
  verifyOtp(@Body() body: OtpDto) {
    return this.auth.verifyOtp(body);
  }

  @Post('pin/verify') // @hit
  verifyPin(@Body() body: PinDto) {
    return this.auth.verifyPin(body);
  }

  @Post('password/forgot') // @hit
  forgotPassword(@Body() body: ForgotDto) {
    return this.auth.sendReset(body.email);
  }

  @Post('refresh')
  refresh(@Body() body: RefreshDto) {
    return this.auth.refresh(body.token);
  }
}
