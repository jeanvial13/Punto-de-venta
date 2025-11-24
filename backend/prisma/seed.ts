import type { PrismaClient } from '@prisma/client';

async function seed(prisma: PrismaClient) {
    // Create Roles
    const adminRole = await prisma.role.create({
        data: {
            name: 'ADMIN',
            permissions: ['ALL'],
        },
    });

    const cashierRole = await prisma.role.create({
        data: {
            name: 'CASHIER',
            permissions: ['SALES', 'CLIENTS'],
        },
    });

    const supervisorRole = await prisma.role.create({
        data: {
            name: 'SUPERVISOR',
            permissions: ['SALES', 'CLIENTS', 'REPORTS'],
        },
    });

    const inventoryRole = await prisma.role.create({
        data: {
            name: 'INVENTORY',
            permissions: ['PRODUCTS', 'INVENTORY'],
        },
    });

    // Create Admin User (password: admin123)
    await prisma.user.create({
        data: {
            email: 'admin@pos.com',
            password: '$2a$10$LKQy.zK5aJ4wZ4zA03DQU.8P0fWJ46YfYkZNPyh0ITRXE4y3wQDXy',
            name: 'Administrator',
            roleId: adminRole.id,
        },
    });

    // Create Categories
    const electronicsCategory = await prisma.category.create({
        data: {
            name: 'Electronics',
            description: 'Electronic devices and accessories',
        },
    });

    const clothingCategory = await prisma.category.create({
        data: {
            name: 'Clothing',
            description: 'Apparel and fashion items',
        },
    });

    const foodCategory = await prisma.category.create({
        data: {
            name: 'Food & Beverages',
            description: 'Food and drink products',
        },
    });

    // Create Products
    await prisma.product.createMany({
        data: [
            {
                name: 'Laptop HP',
                barcode: '1234567890123',
                sku: 'LAPTOP-HP-001',
                description: 'HP Laptop 15.6" Intel i5',
                price: 599.99,
                cost: 450.00,
                tax: 16,
                stock: 15,
                minStock: 5,
                categoryId: electronicsCategory.id,
                status: true,
            },
            {
                name: 'Wireless Mouse',
                barcode: '1234567890124',
                sku: 'MOUSE-WL-001',
                description: 'Logitech Wireless Mouse',
                price: 24.99,
                cost: 15.00,
                tax: 16,
                stock: 50,
                minStock: 10,
                categoryId: electronicsCategory.id,
                status: true,
            },
            {
                name: 'T-Shirt Cotton',
                barcode: '1234567890125',
                sku: 'TSHIRT-001',
                description: 'Cotton T-Shirt - Multiple Colors',
                price: 19.99,
                cost: 10.00,
                tax: 16,
                stock: 100,
                minStock: 20,
                categoryId: clothingCategory.id,
                status: true,
            },
            {
                name: 'Coffee Beans 1kg',
                barcode: '1234567890126',
                sku: 'COFFEE-001',
                description: 'Premium Coffee Beans',
                price: 29.99,
                cost: 18.00,
                tax: 8,
                stock: 30,
                minStock: 10,
                categoryId: foodCategory.id,
                status: true,
            },
        ],
    });

    // Create Sample Client
    await prisma.client.create({
        data: {
            name: 'John Doe',
            email: 'john@example.com',
            phone: '555-1234',
            address: '123 Main St',
            taxId: 'TAX123456',
        },
    });

    // Create Sample Supplier
    await prisma.supplier.create({
        data: {
            name: 'Tech Supplies Inc',
            contact: 'Jane Smith',
            email: 'contact@techsupplies.com',
            phone: '555-5678',
            address: '456 Business Ave',
        },
    });

    console.log('Database seeded successfully!');
}

export default seed;
