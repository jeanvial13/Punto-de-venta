import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateInventoryLogDto } from './dto/inventory.dto';

@Injectable()
export class InventoryService {
    constructor(private prisma: PrismaService) { }

    async createInventoryLog(data: CreateInventoryLogDto, userId: number) {
        return this.prisma.$transaction(async (tx) => {
            // Create inventory log
            const log = await tx.inventoryLog.create({
                data: {
                    productId: data.productId,
                    type: data.type,
                    quantity: data.quantity,
                    reason: data.reason,
                    userId,
                },
                include: {
                    product: true,
                    user: true,
                },
            });

            // Update product stock
            const product = await tx.product.findUnique({
                where: { id: data.productId },
            });

            if (!product) {
                throw new Error('Product not found');
            }

            let newStock = product.stock;

            if (data.type === 'IN') {
                newStock += data.quantity;
            } else if (data.type === 'OUT') {
                newStock -= data.quantity;
            } else if (data.type === 'ADJUSTMENT') {
                newStock = data.quantity;
            }

            await tx.product.update({
                where: { id: data.productId },
                data: { stock: newStock },
            });

            return log;
        });
    }

    async getInventoryLogs(filters?: { productId?: number; type?: string }) {
        const where: any = {};

        if (filters?.productId) {
            where.productId = filters.productId;
        }

        if (filters?.type) {
            where.type = filters.type;
        }

        return this.prisma.inventoryLog.findMany({
            where,
            include: {
                product: true,
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                    },
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
            take: 100,
        });
    }

    async getKardex(productId: number) {
        return this.prisma.inventoryLog.findMany({
            where: { productId },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                    },
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
        });
    }
}
