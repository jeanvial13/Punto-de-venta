import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { ProductsModule } from './products/products.module';
import { InventoryModule } from './inventory/inventory.module';
import { ClientsModule } from './clients/clients.module';
import { SalesModule } from './sales/sales.module';
import { CashRegisterModule } from './cash-register/cash-register.module';
import { ReportsModule } from './reports/reports.module';
import { RepairsModule } from './repairs/repairs.module';
import { DevicesModule } from './devices/devices.module';
import { TechniciansModule } from './technicians/technicians.module';

@Module({
  imports: [
    PrismaModule,
    AuthModule,
    ProductsModule,
    InventoryModule,
    ClientsModule,
    SalesModule,
    CashRegisterModule,
    ReportsModule,
    RepairsModule,
    DevicesModule,
    TechniciansModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
