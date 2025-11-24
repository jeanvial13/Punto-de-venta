import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
    CreateClientDto,
    UpdateClientDto,
    CreateSupplierDto,
    UpdateSupplierDto,
} from './dto/client.dto';

@Injectable()
export class ClientsService {
    constructor(private prisma: PrismaService) { }

    // Clients
    async createClient(data: CreateClientDto) {
        return this.prisma.client.create({
            data,
        });
    }

    async findAllClients(search?: string) {
        const where: any = {};

        if (search) {
            where.OR = [
                { name: { contains: search, mode: 'insensitive' } },
                { email: { contains: search, mode: 'insensitive' } },
                { phone: { contains: search, mode: 'insensitive' } },
            ];
        }

        return this.prisma.client.findMany({
            where,
            include: {
                _count: {
                    select: { sales: true },
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
        });
    }

    async findClientById(id: number) {
        return this.prisma.client.findUnique({
            where: { id },
            include: {
                sales: {
                    take: 10,
                    orderBy: { createdAt: 'desc' },
                },
            },
        });
    }

    async updateClient(id: number, data: UpdateClientDto) {
        return this.prisma.client.update({
            where: { id },
            data,
        });
    }

    async deleteClient(id: number) {
        return this.prisma.client.delete({
            where: { id },
        });
    }

    // Suppliers
    async createSupplier(data: CreateSupplierDto) {
        return this.prisma.supplier.create({
            data,
        });
    }

    async findAllSuppliers(search?: string) {
        const where: any = {};

        if (search) {
            where.OR = [
                { name: { contains: search, mode: 'insensitive' } },
                { email: { contains: search, mode: 'insensitive' } },
                { phone: { contains: search, mode: 'insensitive' } },
            ];
        }

        return this.prisma.supplier.findMany({
            where,
            include: {
                _count: {
                    select: { purchases: true },
                },
            },
            orderBy: {
                createdAt: 'desc',
            },
        });
    }

    async findSupplierById(id: number) {
        return this.prisma.supplier.findUnique({
            where: { id },
            include: {
                purchases: {
                    take: 10,
                    orderBy: { createdAt: 'desc' },
                },
            },
        });
    }

    async updateSupplier(id: number, data: UpdateSupplierDto) {
        return this.prisma.supplier.update({
            where: { id },
            data,
        });
    }

    async deleteSupplier(id: number) {
        return this.prisma.supplier.delete({
            where: { id },
        });
    }
}
