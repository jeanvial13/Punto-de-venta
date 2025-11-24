import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class TechniciansService {
    constructor(private prisma: PrismaService) { }

    async createTechnician(userId: number, specializations: string[]) {
        return this.prisma.technician.create({
            data: {
                userId,
                specializations,
            },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                    },
                },
            },
        });
    }

    async findAllTechnicians(activeOnly: boolean = true) {
        return this.prisma.technician.findMany({
            where: activeOnly ? { isActive: true } : {},
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                    },
                },
                _count: {
                    select: {
                        repairs: {
                            where: {
                                status: {
                                    notIn: ['DELIVERED', 'CANCELED'],
                                },
                            },
                        },
                    },
                },
            },
        });
    }

    async findTechnicianById(id: number) {
        return this.prisma.technician.findUnique({
            where: { id },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                    },
                },
            },
        });
    }

    async getAssignedRepairs(technicianId: number) {
        return this.prisma.repair.findMany({
            where: {
                technicianId,
                status: {
                    notIn: ['DELIVERED', 'CANCELED'],
                },
            },
            include: {
                client: true,
                device: true,
                items: {
                    include: {
                        product: true,
                    },
                },
            },
            orderBy: {
                estimatedDelivery: 'asc',
            },
        });
    }

    async getPendingTasks(technicianId: number) {
        return this.prisma.repair.findMany({
            where: {
                technicianId,
                status: {
                    in: ['DIAGNOSING', 'IN_REPAIR', 'SOFTWARE_REPAIR', 'QUALITY_CHECK'],
                },
            },
            include: {
                client: true,
                device: true,
            },
            orderBy: {
                createdAt: 'asc',
            },
        });
    }

    async updateTechnician(id: number, data: { specializations?: string[]; isActive?: boolean }) {
        return this.prisma.technician.update({
            where: { id },
            data,
            include: {
                user: true,
            },
        });
    }
}
