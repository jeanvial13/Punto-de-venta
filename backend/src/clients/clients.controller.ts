import {
    Controller,
    Get,
    Post,
    Put,
    Delete,
    Body,
    Param,
    Query,
    UseGuards,
} from '@nestjs/common';
import { ClientsService } from './clients.service';
import {
    CreateClientDto,
    UpdateClientDto,
    CreateSupplierDto,
    UpdateSupplierDto,
} from './dto/client.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('clients')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ClientsController {
    constructor(private clientsService: ClientsService) { }

    @Post()
    @Roles('ADMIN', 'CASHIER')
    createClient(@Body() createClientDto: CreateClientDto) {
        return this.clientsService.createClient(createClientDto);
    }

    @Get()
    findAllClients(@Query('search') search?: string) {
        return this.clientsService.findAllClients(search);
    }

    @Get(':id')
    findClientById(@Param('id') id: string) {
        return this.clientsService.findClientById(parseInt(id));
    }

    @Put(':id')
    @Roles('ADMIN', 'CASHIER')
    updateClient(@Param('id') id: string, @Body() updateClientDto: UpdateClientDto) {
        return this.clientsService.updateClient(parseInt(id), updateClientDto);
    }

    @Delete(':id')
    @Roles('ADMIN')
    deleteClient(@Param('id') id: string) {
        return this.clientsService.deleteClient(parseInt(id));
    }
}

@Controller('suppliers')
@UseGuards(JwtAuthGuard, RolesGuard)
export class SuppliersController {
    constructor(private clientsService: ClientsService) { }

    @Post()
    @Roles('ADMIN', 'INVENTORY')
    createSupplier(@Body() createSupplierDto: CreateSupplierDto) {
        return this.clientsService.createSupplier(createSupplierDto);
    }

    @Get()
    findAllSuppliers(@Query('search') search?: string) {
        return this.clientsService.findAllSuppliers(search);
    }

    @Get(':id')
    findSupplierById(@Param('id') id: string) {
        return this.clientsService.findSupplierById(parseInt(id));
    }

    @Put(':id')
    @Roles('ADMIN', 'INVENTORY')
    updateSupplier(@Param('id') id: string, @Body() updateSupplierDto: UpdateSupplierDto) {
        return this.clientsService.updateSupplier(parseInt(id), updateSupplierDto);
    }

    @Delete(':id')
    @Roles('ADMIN')
    deleteSupplier(@Param('id') id: string) {
        return this.clientsService.deleteSupplier(parseInt(id));
    }
}
