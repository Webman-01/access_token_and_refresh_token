import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Observable } from 'rxjs';

@Injectable()
export class LoginGuard implements CanActivate {
  @Inject(JwtService)
  private jwtService: JwtService;
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: Request = context.switchToHttp().getRequest();
    const authorization = request.headers.authorization;
    //取出 authorization header 中的 jwt token，这个就是 access_token，对它做校验。
    //jwt 有效就可以继续访问，否则返回 token 失效，请重新登录
    if (!authorization) {
      throw new UnauthorizedException('用户未登陆');
    }
    try {
      const token = authorization.split(' ')[1];
      const data = this.jwtService.verify(token); //解码后的令牌对象
      return true;
    } catch (error) {
      throw new UnauthorizedException('token失效,请重新登陆');
    }
    return true;
  }
}
