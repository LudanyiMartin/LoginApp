import { Injectable } from '@nestjs/common';
import { LoginDto } from './LoginDto';
import { PrismaService } from 'src/prisma.service';
import * as asrgon2 from "argon2"
import * as crypto from "node:crypto"

@Injectable()
export class AuthService {
  constructor(private readonly db: PrismaService){}
  
  async login(loginData: LoginDto){
    const user =  await this.db.user.findUniqueOrThrow({
      where: { email: loginData.email }
    })
    if(await asrgon2.verify(user.password, loginData.password)){
      const token = crypto.randomBytes(64).toString("hex");
      this.db.token.create({
        data: [
          token,
          user: { connect: {id: user.id } }
        ]
      })
      return {
        token,
        userId: user.id
      }
    } else{
      throw new Error("Wrong Password")
    }
  }
}
