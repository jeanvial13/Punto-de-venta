import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateProductDto, UpdateProductDto } from './dto/product.dto';
import { CreateCategoryDto, UpdateCategoryDto } from './dto/category.dto';

@Injectable()
export class ProductsService {
    constructor(private prisma: PrismaService) { }

    // Products
    async createProduct(data: CreateProductDto) {
        return this.prisma.product.create({
            data: {
                ...data,
                price: data.price,
                cost: data.cost,
            },
            include: {
                category: true,
            },
        });
    }

    async findAllProducts(filters?: { categoryId?: number; status?: boolean; search?: string }) {
        const where: any = {};

        if (filters?.categoryId) {
            where.categoryId = filters.categoryId;
        }

        if (filters?.status !== undefined) {
            where.status = filters.status;
        }

        if (filters?.search) {
            where.OR = [
                { name: { contains: filters.search, mode: 'insensitive' } },
                { barcode: { contains: filters.search, mode: 'insensitive' } },
                { sku: { contains: filters.search, mode: 'insensitive' } },
            ];
        }

        return this.prisma.product.findMany({
            where,
            include: {
                category: true,
            },
            orderBy: {
                createdAt: 'desc',
            },
        });
    }

    async findProductById(id: number) {
        return this.prisma.product.findUnique({
            where: { id },
            include: {
                category: true,
                inventoryLogs: {
                    take: 10,
                    orderBy: { createdAt: 'desc' },
                },
            },
        });
    }

    async updateProduct(id: number, data: UpdateProductDto) {
        return this.prisma.product.update({
            where: { id },
            data,
            include: {
                category: true,
            },
        });
    }

    async deleteProduct(id: number) {
        return this.prisma.product.delete({
            where: { id },
        });
    }

    async getLowStockProducts() {
        return this.prisma.product.findMany({
            where: {
                stock: {
                    lte: this.prisma.product.fields.minStock,
                },
                status: true,
            },
            include: {
                category: true,
            },
        });
    }

    // Categories
    async createCategory(data: CreateCategoryDto) {
        return this.prisma.category.create({
            data,
        });
    }

    async findAllCategories() {
        return this.prisma.category.findMany({
            include: {
                _count: {
                    select: { products: true },
                },
            },
            orderBy: {
                name: 'asc',
            },
        });
    }

    async findCategoryById(id: number) {
        return this.prisma.category.findUnique({
            where: { id },
            include: {
                products: true,
            },
        });
    }

    async updateCategory(id: number, data: UpdateCategoryDto) {
        return this.prisma.category.update({
            where: { id },
            data,
        });
    }

    async deleteCategory(id: number) {
        return this.prisma.category.delete({
            where: { id },
        });
    }
}
