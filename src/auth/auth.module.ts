import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { PassportModule } from '@nestjs/passport';

@Module({
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
  imports: [
    JwtModule.register({
      secret: 'secretKey', // Replace with a secure key in production
      signOptions: { expiresIn: '60s' },
    }),
    PassportModule,
  ],
})
export class AuthModule {}
