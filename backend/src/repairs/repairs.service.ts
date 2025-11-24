import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
    CreateRepairDto,
    UpdateRepairDto,
    AddRepairItemDto,
    AddSoftwareActionDto,
    ChangeStatusDto,
    AddRepairNoteDto,
    DeliverRepairDto,
} from './dto/repair.dto';

@Injectable()
export class RepairsService {
    constructor(private prisma: PrismaService) { }

    async createRepair(data: CreateRepairDto, userId: number) {
        // Generate ticket number
        const ticketNumber = `REP-${Date.now()}`;

        return this.prisma.repair.create({
            data: {
                ticketNumber,
                clientId: data.clientId,
                deviceId: data.deviceId,
                technicianId: data.technicianId,
                reportedIssue: data.reportedIssue,
                diagnosticInitial: data.diagnosticInitial,
                estimatedCost: data.estimatedCost,
                estimatedDelivery: data.estimatedDelivery ? new Date(data.estimatedDelivery) : null,
                warranty: data.warranty,
                status: 'RECEIVED',
                statusLogs: {
                    create: {
                        status: 'RECEIVED',
                        userId,
                        notes: 'Repair order created',
                    },
                },
            },
            include: {
                client: true,
                device: {
                    include: {
                        photos: true,
                    },
                },
                technician: {
                    include: {
                        user: {
                            select: {
                                id: true,
                                name: true,
                                email: true,
                            },
                        },
                    },
                },
            },
        });
    }

    async findAllRepairs(filters?: {
        status?: string;
        technicianId?: number;
        clientId?: number;
        startDate?: Date;
        endDate?: Date;
    }) {
        const where: any = {};

        if (filters?.status) {
            where.status = filters.status;
        }

        if (filters?.technicianId) {
            where.technicianId = filters.technicianId;
        }

        if (filters?.clientId) {
            where.clientId = filters.clientId;
        }

        if (filters?.startDate || filters?.endDate) {
            where.createdAt = {};
            if (filters.startDate) where.createdAt.gte = filters.startDate;
            if (filters.endDate) where.createdAt.lte = filters.endDate;
        }

        return this.prisma.repair.findMany({
            where,
            include: {
                client: true,
                device: true,
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
                _count: {
                    select: {
                        notes: true,
                    },
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
        });
    }

    async findRepairById(id: number) {
        return this.prisma.repair.findUnique({
            where: { id },
            include: {
                client: true,
                device: {
                    include: {
                        photos: true,
                    },
                },
                technician: {
                    include: {
                        user: {
                            select: {
                                id: true,
                                name: true,
                                email: true,
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
                    include: {
                        changedBy: {
                            select: {
                                id: true,
                                name: true,
                            },
                        },
                    },
                    orderBy: {
                        createdAt: 'desc',
                    },
                },
                notes: {
                    include: {
                        createdBy: {
                            select: {
                                id: true,
                                name: true,
                            },
                        },
                    },
                    orderBy: {
                        createdAt: 'desc',
                    },
                },
            },
        });
    }

    async updateRepair(id: number, data: UpdateRepairDto) {
        return this.prisma.repair.update({
            where: { id },
            data,
            include: {
                client: true,
                device: true,
                technician: {
                    include: {
                        user: true,
                    },
                },
            },
        });
    }

    async changeStatus(id: number, data: ChangeStatusDto, userId: number) {
        return this.prisma.$transaction(async (tx) => {
            // Update repair status
            const repair = await tx.repair.update({
                where: { id },
                data: {
                    status: data.status,
                },
            });

            // Log status change
            await tx.repairStatusLog.create({
                data: {
                    repairId: id,
                    status: data.status,
                    userId,
                    notes: data.notes,
                },
            });

            return repair;
        });
    }

    async addRepairItem(repairId: number, data: AddRepairItemDto) {
        return this.prisma.$transaction(async (tx) => {
            // Add item to repair
            const repairItem = await tx.repairItem.create({
                data: {
                    repairId,
                    productId: data.productId,
                    quantity: data.quantity,
                    cost: data.cost,
                    warranty: data.warranty,
                },
                include: {
                    product: true,
                },
            });

            // Decrease inventory
            await tx.product.update({
                where: { id: data.productId },
                data: {
                    stock: {
                        decrement: data.quantity,
                    },
                },
            });

            // Create inventory log
            await tx.inventoryLog.create({
                data: {
                    productId: data.productId,
                    type: 'OUT',
                    quantity: data.quantity,
                    reason: `Used in repair #${repairId}`,
                    userId: 1, // TODO: Get from context
                },
            });

            return repairItem;
        });
    }

    async addSoftwareAction(repairId: number, data: AddSoftwareActionDto) {
        return this.prisma.repairSoftwareAction.create({
            data: {
                repairId,
                serviceType: data.serviceType,
                cost: data.cost,
                notes: data.notes,
                legalAuthorization: data.legalAuthorization || false,
            },
        });
    }

    async addNote(repairId: number, data: AddRepairNoteDto, userId: number) {
        return this.prisma.repairNote.create({
            data: {
                repairId,
                content: data.content,
                isInternal: data.isInternal,
                userId,
            },
            include: {
                createdBy: {
                    select: {
                        id: true,
                        name: true,
                    },
                },
            },
        });
    }

    async deliverRepair(id: number, data: DeliverRepairDto, userId: number) {
        return this.prisma.repair.update({
            where: { id },
            data: {
                finalCost: data.finalCost,
                status: 'DELIVERED',
                deliveredAt: new Date(),
                signaturePhoto: data.signaturePhoto,
                statusLogs: {
                    create: {
                        status: 'DELIVERED',
                        userId,
                        notes: 'Repair delivered to customer',
                    },
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
                softwareActions: true,
            },
        });
    }

    async getRepairHistory(deviceId?: number, clientId?: number) {
        const where: any = {};

        if (deviceId) where.deviceId = deviceId;
        if (clientId) where.clientId = clientId;

        return this.prisma.repair.findMany({
            where,
            include: {
                device: true,
                items: {
                    include: {
                        product: true,
                    },
                },
                softwareActions: true,
            },
            orderBy: {
                createdAt: 'desc',
            },
        });
    }

    async cancelRepair(id: number, userId: number) {
        return this.prisma.$transaction(async (tx) => {
            const repair = await tx.repair.findUnique({
                where: { id },
                include: {
                    items: true,
                },
            });

            if (!repair) {
                throw new Error('Repair not found');
            }

            // Restore parts to inventory
            for (const item of repair.items) {
                await tx.product.update({
                    where: { id: item.productId },
                    data: {
                        stock: {
                            increment: item.quantity,
                        },
                    },
                });
            }

            // Update status
            return tx.repair.update({
                where: { id },
                data: {
                    status: 'CANCELED',
                    statusLogs: {
                        create: {
                            status: 'CANCELED',
                            userId,
                            notes: 'Repair canceled',
                        },
                    },
                },
            });
        });
    }
}
