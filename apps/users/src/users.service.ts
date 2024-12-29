import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ActivationDto, LoginDto, RegisterDto } from './dto/user.dto';
import { PrismaService } from '../../../prisma/Prisma.service';
import { Response } from 'express';
import { hash, compare } from 'bcrypt';
import { EmailService } from './email/email.service';
import { TokenSender } from './utils/sendToken';

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number: number;
}

@Injectable()
export class UsersService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  async register(registerDto: RegisterDto, response: Response) {
    const { email, name, password, phone_number } = registerDto;

    const isEmailExists = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (isEmailExists) {
      throw new BadRequestException('User already exist with that email');
    }

    const phoneNumbersToCheck = [phone_number];

    const usersWithPhoneNumber = await this.prisma.user.findMany({
      where: {
        phone_number: {
          not: null,
          in: phoneNumbersToCheck,
        },
      },
    });

    if (usersWithPhoneNumber.length > 0) {
      throw new BadRequestException(
        'User already exist with this phone number!',
      );
    }

    const hashedPassword = await hash(password, 10);

    const user = {
      name,
      email,
      password: hashedPassword,
      phone_number,
    };

    const activationToken = await this.createActivationToken(user);

    const activationCode = activationToken.activationCode;

    await this.emailService.sendMail({
      email,
      subject: 'Activate your account!',
      name: name,
      activationCode,
      template: '../food-service/email-templates/activation-mail',
    });

    return { activation_token: activationToken.token, response };
  }

  async createActivationToken(user: UserData) {
    const activationCode = Math.floor(1000 + Math.random() * 9000).toString();

    const token = this.jwtService.sign(
      { user, activationCode },
      { secret: this.configService.get('ACTIVATION_SECRET'), expiresIn: '5m' },
    );

    return { token, activationCode };
  }

  async activateUser(activationDto: ActivationDto, response: Response) {
    const { activationCode, activationToken } = activationDto;

    const newUser: { user: UserData; activationCode: string } =
      this.jwtService.verify(activationToken, {
        secret: this.configService.get<string>('ACTIVATION_SECRET'),
      });

    if (newUser.activationCode !== activationCode) {
      throw new BadRequestException('Invalid activation code');
    }

    const { email, name, password, phone_number } = newUser.user;

    const existUser = await this.prisma.user.findUnique({ where: { email } });

    if (existUser) {
      throw new BadRequestException('User already exist with this email');
    }

    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        password,
        phone_number,
      },
    });

    return { user, response };
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    const user = await this.prisma.user.findUnique({ where: { email } });

    if (user && (await this.comparePassword(password, user.password))) {
      const tokenSender = new TokenSender(this.configService, this.jwtService);
      const { accessToken, refreshToken } = tokenSender.sendToken(user);
      return { user, accessToken, refreshToken };
    } else {
      return {
        user: null,
        accessToken: null,
        refreshToken: null,
        error: { message: 'Invalid email or password' },
      };
    }
  }

  async logout(req: any) {
    req.user = null;
    req.refreshToken = null;
    req.accessToken = null;
    return { message: 'Logged out successfully' };
  }

  async getLoggedInUser(req: any) {
    const user = req.user;
    const accessToken = req.accessToken;
    const refreshToken = req.refreshToken;

    return { user, accessToken, refreshToken };
  }

  async comparePassword(
    password: string,
    hasedPassword: string,
  ): Promise<boolean> {
    return await compare(password, hasedPassword);
  }

  async getUsers() {
    return await this.prisma.user.findMany();
  }
}
