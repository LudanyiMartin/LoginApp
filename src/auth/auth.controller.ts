import { Body, Controller, Post, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './LoginDto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post("login")
  async login(@Body() loginData: LoginDto){
    try{
      return await this.authService.login(loginData)
    } catch{
      throw new UnauthorizedException("Hibás email, vagy jelszó!!!👩🏿‍💻")
    }
  }
}
