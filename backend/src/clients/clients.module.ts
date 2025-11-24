import { Module } from '@nestjs/common';
import { ClientsService } from './clients.service';
import { ClientsController, SuppliersController } from './clients.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
    imports: [PrismaModule],
    controllers: [ClientsController, SuppliersController],
    providers: [ClientsService],
    exports: [ClientsService],
})
export class ClientsModule { }
