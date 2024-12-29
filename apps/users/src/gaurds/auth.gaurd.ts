import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { GqlExecutionContext } from '@nestjs/graphql';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../../prisma/Prisma.service';
import { User } from '@prisma/client';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const gqlContext = GqlExecutionContext.create(context);
    const { req } = gqlContext.getContext();

    const accessToken = req.headers.accesstoken as string;
    const refreshToken = req.headers.refreshtoken as string;

    if (!accessToken || !refreshToken) {
      throw new UnauthorizedException('Please login to access this resource!');
    }

    if (accessToken) {
      const decoded = this.jwtService.decode(accessToken);

      if(!decoded) {
        throw new UnauthorizedException("Wrong Token!")
      }

      const expirationTime = decoded?.exp;

      const user = await this.prisma.user.findUnique({
        where: {
          id: decoded.id,
        },
      });

      req.accessToken = accessToken;
      req.refreshToken = refreshToken;
      req.user = user

      if (expirationTime * 1000 < Date.now()) {
        await this.updateAccessToken(req, user);
      }
    }

    return true;
  }

  private async updateAccessToken(req: any, user: User): Promise<void> {
    try {
      const refreshTokenData = req.headers.refreshToken as string;
      const decoded = this.jwtService.verify(refreshTokenData, {
        secret: this.config.get('REFRESH_TOKEN_SECRET'),
      });

      if (!decoded) {
        throw new UnauthorizedException('Invalid Refresh Token');
      }

      const accessToken = this.jwtService.sign(
        { id: user.id },
        {
          secret: this.config.get('ACCESS_TOKEN_SECRET'),
          expiresIn: '15m',
        },
      );

      const refreshToken = this.jwtService.sign(
        { id: user.id },
        {
          secret: this.config.get('REFRESH_TOKEN_SECRET'),
          expiresIn: '7d',
        },
      );

      req.accessToken = accessToken;
      req.refreshToken = refreshToken;
      req.user = user;
    } catch (error) {
      console.log(error);
    }
  }
}
