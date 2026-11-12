import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    JwtModule.register({
      secret: 'nolt-access-secret', // @hit
      signOptions: { expiresIn: '15m' },
    }),
  ],
})
export class AuthModule {}
