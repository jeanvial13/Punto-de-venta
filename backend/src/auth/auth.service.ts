import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import { RegisterDto, LoginDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
    ) { }

    async register(data: RegisterDto) {
        const hashedPassword = await bcrypt.hash(data.password, 10);

        // Default to roleId 2 (CASHIER) if not provided
        const roleId = data.roleId || 2;

        const user = await this.prisma.user.create({
            data: {
                email: data.email,
                password: hashedPassword,
                name: data.name,
                roleId,
            },
            include: {
                role: true,
            },
        });

        const { password, ...result } = user;
        return result;
    }

    async login(data: LoginDto) {
        const user = await this.prisma.user.findUnique({
            where: { email: data.email },
            include: { role: true },
        });

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const isPasswordValid = await bcrypt.compare(data.password, user.password);

        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const payload = { sub: user.id, email: user.email, role: user.role.name };
        const token = this.jwtService.sign(payload);

        const { password, ...result } = user;

        return {
            access_token: token,
            user: result,
        };
    }

    async validateUser(userId: number) {
        const user = await this.prisma.user.findUnique({
            where: { id: userId },
            include: { role: true },
        });

        if (!user) {
            return null;
        }

        const { password, ...result } = user;
        return result;
    }
}
