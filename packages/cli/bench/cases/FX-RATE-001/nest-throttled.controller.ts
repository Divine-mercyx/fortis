import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

@UseGuards(ThrottlerGuard)
@Controller('pin')
export class PinController {
  @Post('verify')
  verify(@Body() body: PinDto) {
    return this.pins.verify(body);
  }

  @Post('otp')
  otp(@Body() body: OtpDto) {
    return this.pins.verifyOtp(body);
  }
}
