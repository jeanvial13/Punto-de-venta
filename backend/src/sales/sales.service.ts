import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateSaleDto } from './dto/sale.dto';

@Injectable()
export class SalesService {
    constructor(private prisma: PrismaService) { }

    async createSale(data: CreateSaleDto, userId: number) {
        return this.prisma.$transaction(async (tx) => {
            // Generate ticket number
            const ticketNumber = `TICKET-${Date.now()}`;

            // Calculate totals
            let subtotal = 0;
            let totalTax = 0;

            const saleItems: Array<{
                productId: number;
                quantity: number;
                price: number;
                total: number;
            }> = [];

            for (const item of data.items) {
                const product = await tx.product.findUnique({
                    where: { id: item.productId },
                });

                if (!product) {
                    throw new Error(`Product ${item.productId} not found`);
                }

                if (product.stock < item.quantity) {
                    throw new Error(`Insufficient stock for product ${product.name}`);
                }

                const itemTotal = item.price * item.quantity;
                const itemTax = (itemTotal * Number(product.tax)) / 100;

                subtotal += itemTotal;
                totalTax += itemTax;

                saleItems.push({
                    productId: item.productId,
                    quantity: item.quantity,
                    price: item.price,
                    total: itemTotal,
                });

                // Update product stock
                await tx.product.update({
                    where: { id: item.productId },
                    data: {
                        stock: {
                            decrement: item.quantity,
                        },
                    },
                });

                // Create inventory log
                await tx.inventoryLog.create({
                    data: {
                        productId: item.productId,
                        type: 'OUT',
                        quantity: item.quantity,
                        reason: `Sale ${ticketNumber}`,
                        userId,
                    },
                });
            }

            const discount = data.discount || 0;
            const total = subtotal + totalTax - discount;

            // Create sale
            const sale = await tx.sale.create({
                data: {
                    ticketNumber,
                    total,
                    tax: totalTax,
                    discount,
                    paymentMethod: data.paymentMethod,
                    status: 'COMPLETED',
                    userId,
                    clientId: data.clientId,
                    items: {
                        create: saleItems,
                    },
                },
                include: {
                    items: {
                        include: {
                            product: true,
                        },
                    },
                    client: true,
                    user: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                        },
                    },
                },
            });

            return sale;
        });
    }

    async getSales(filters?: {
        startDate?: Date;
        endDate?: Date;
        userId?: number;
        status?: string;
    }) {
        const where: any = {};

        if (filters?.startDate || filters?.endDate) {
            where.createdAt = {};
            if (filters.startDate) where.createdAt.gte = filters.startDate;
            if (filters.endDate) where.createdAt.lte = filters.endDate;
        }

        if (filters?.userId) {
            where.userId = filters.userId;
        }

        if (filters?.status) {
            where.status = filters.status;
        }

        return this.prisma.sale.findMany({
            where,
            include: {
                items: {
                    include: {
                        product: true,
                    },
                },
                client: true,
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

    async getSaleById(id: number) {
        return this.prisma.sale.findUnique({
            where: { id },
            include: {
                items: {
                    include: {
                        product: true,
                    },
                },
                client: true,
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

    async cancelSale(id: number) {
        return this.prisma.$transaction(async (tx) => {
            const sale = await tx.sale.findUnique({
                where: { id },
                include: {
                    items: true,
                },
            });

            if (!sale) {
                throw new Error('Sale not found');
            }

            if (sale.status === 'CANCELED') {
                throw new Error('Sale already canceled');
            }

            // Restore stock
            for (const item of sale.items) {
                await tx.product.update({
                    where: { id: item.productId },
                    data: {
                        stock: {
                            increment: item.quantity,
                        },
                    },
                });
            }

            // Update sale status
            return tx.sale.update({
                where: { id },
                data: {
                    status: 'CANCELED',
                },
                include: {
                    items: {
                        include: {
                            product: true,
                        },
                    },
                    client: true,
                },
            });
        });
    }
}
