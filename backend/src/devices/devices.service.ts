import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateDeviceDto } from '../repairs/dto/repair.dto';

@Injectable()
export class DevicesService {
    constructor(private prisma: PrismaService) { }

    async createDevice(data: CreateDeviceDto) {
        return this.prisma.device.create({
            data,
            include: {
                client: true,
            },
        });
    }

    async findDeviceById(id: number) {
        return this.prisma.device.findUnique({
            where: { id },
            include: {
                client: true,
                photos: true,
                repairs: {
                    orderBy: {
                        createdAt: 'desc',
                    },
                },
            },
        });
    }

    async findDeviceByIMEI(imei: string) {
        return this.prisma.device.findUnique({
            where: { imei },
            include: {
                client: true,
                photos: true,
                repairs: {
                    orderBy: {
                        createdAt: 'desc',
                    },
                    take: 5,
                },
            },
        });
    }

    async uploadDevicePhoto(deviceId: number, photoUrl: string, photoType: string) {
        return this.prisma.devicePhoto.create({
            data: {
                deviceId,
                photoUrl,
                photoType,
            },
        });
    }

    async getDeviceRepairHistory(deviceId: number) {
        return this.prisma.repair.findMany({
            where: { deviceId },
            include: {
                technician: {
                    include: {
                        user: {
                            select: {
                                id: true,
                                name: true,
                            },
                        },
                    },
                },
                items: {
                    include: {
                        product: true,
                    },
                },
                softwareActions: true,
                statusLogs: {
                    orderBy: {
                        createdAt: 'desc',
                    },
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
        });
    }
}
