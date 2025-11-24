import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
    OpenRegisterDto,
    CloseRegisterDto,
    CreateCashMovementDto,
} from './dto/cash-register.dto';

@Injectable()
export class CashRegisterService {
    constructor(private prisma: PrismaService) { }

    async openRegister(data: OpenRegisterDto, userId: number) {
        // Check if user already has an open register
        const existingRegister = await this.prisma.cashRegister.findFirst({
            where: {
                userId,
                status: 'OPEN',
            },
        });

        if (existingRegister) {
            throw new Error('User already has an open register');
        }

        return this.prisma.cashRegister.create({
            data: {
                userId,
                startAmount: data.startAmount,
                status: 'OPEN',
            },
        });
    }

    async closeRegister(registerId: number, data: CloseRegisterDto) {
        const register = await this.prisma.cashRegister.findUnique({
            where: { id: registerId },
        });

        if (!register) {
            throw new Error('Register not found');
        }

        if (register.status === 'CLOSED') {
            throw new Error('Register already closed');
        }

        return this.prisma.cashRegister.update({
            where: { id: registerId },
            data: {
                endAmount: data.endAmount,
                endTime: new Date(),
                status: 'CLOSED',
            },
            include: {
                movements: true,
            },
        });
    }

    async createCashMovement(data: CreateCashMovementDto) {
        return this.prisma.cashMovement.create({
            data,
        });
    }

    async getCurrentRegister(userId: number) {
        return this.prisma.cashRegister.findFirst({
            where: {
                userId,
                status: 'OPEN',
            },
            include: {
                movements: {
                    orderBy: {
                        createdAt: 'desc',
                    },
                },
            },
        });
    }

    async getRegisterHistory(userId?: number) {
        const where: any = { status: 'CLOSED' };

        if (userId) {
            where.userId = userId;
        }

        return this.prisma.cashRegister.findMany({
            where,
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                    },
                },
                movements: true,
            },
            orderBy: {
                startTime: 'desc',
            },
            take: 50,
        });
    }
}
