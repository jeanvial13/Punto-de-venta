import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ReportsService {
    constructor(private prisma: PrismaService) { }

    async getDashboardKPIs() {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);

        // Today's sales
        const todaySalesData = await this.prisma.sale.aggregate({
            where: {
                createdAt: {
                    gte: today,
                    lt: tomorrow,
                },
                status: 'COMPLETED',
            },
            _sum: {
                total: true,
            },
            _count: true,
        });

        // Low stock products
        const lowStockCount = await this.prisma.product.count({
            where: {
                stock: {
                    lte: this.prisma.product.fields.minStock,
                },
                status: true,
            },
        });

        // Total products
        const totalProducts = await this.prisma.product.count({
            where: { status: true },
        });

        // Total clients
        const totalClients = await this.prisma.client.count();

        return {
            todaySales: todaySalesData._sum.total || 0,
            todaySalesCount: todaySalesData._count,
            lowStockProducts: lowStockCount,
            totalProducts,
            totalClients,
        };
    }

    async getSalesByPeriod(startDate: Date, endDate: Date) {
        const sales = await this.prisma.sale.findMany({
            where: {
                createdAt: {
                    gte: startDate,
                    lte: endDate,
                },
                status: 'COMPLETED',
            },
            include: {
                items: {
                    include: {
                        product: true,
                    },
                },
                user: {
                    select: {
                        id: true,
                        name: true,
                    },
                },
            },
        });

        const totalSales = sales.reduce((sum, sale) => sum + Number(sale.total), 0);
        const totalTax = sales.reduce((sum, sale) => sum + Number(sale.tax), 0);
        const totalDiscount = sales.reduce((sum, sale) => sum + Number(sale.discount), 0);

        return {
            sales,
            summary: {
                totalSales,
                totalTax,
                totalDiscount,
                count: sales.length,
            },
        };
    }

    async getTopProducts(limit: number = 10) {
        const topProducts = await this.prisma.saleItem.groupBy({
            by: ['productId'],
            _sum: {
                quantity: true,
                total: true,
            },
            orderBy: {
                _sum: {
                    total: 'desc',
                },
            },
            take: limit,
        });

        const productsWithDetails = await Promise.all(
            topProducts.map(async (item) => {
                const product = await this.prisma.product.findUnique({
                    where: { id: item.productId },
                });
                return {
                    product,
                    quantity: item._sum.quantity,
                    total: item._sum.total,
                };
            }),
        );

        return productsWithDetails;
    }

    async getSalesByCategory() {
        const salesByCategory = await this.prisma.saleItem.findMany({
            include: {
                product: {
                    include: {
                        category: true,
                    },
                },
            },
        });

        const categoryMap: Record<string, { name: string; total: number; quantity: number }> = {};

        salesByCategory.forEach((item) => {
            const categoryName = item.product.category?.name || 'Uncategorized';

            if (!categoryMap[categoryName]) {
                categoryMap[categoryName] = {
                    name: categoryName,
                    total: 0,
                    quantity: 0,
                };
            }

            categoryMap[categoryName].total += Number(item.total);
            categoryMap[categoryName].quantity += item.quantity;
        });

        return Object.values(categoryMap).sort((a, b) => b.total - a.total);
    }

    async getInventoryValuation() {
        const products = await this.prisma.product.findMany({
            where: { status: true },
        });

        const totalValue = products.reduce(
            (sum, product) => sum + Number(product.cost) * product.stock,
            0,
        );

        const totalRetailValue = products.reduce(
            (sum, product) => sum + Number(product.price) * product.stock,
            0,
        );

        return {
            totalValue,
            totalRetailValue,
            products: products.map((p) => ({
                id: p.id,
                name: p.name,
                stock: p.stock,
                cost: p.cost,
                value: Number(p.cost) * p.stock,
            })),
        };
    }
}
