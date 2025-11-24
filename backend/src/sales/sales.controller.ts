import {
    Controller,
    Get,
    Post,
    Put,
    Body,
    Param,
    Query,
    UseGuards,
    Request,
} from '@nestjs/common';
import { SalesService } from './sales.service';
import { CreateSaleDto } from './dto/sale.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('sales')
@UseGuards(JwtAuthGuard, RolesGuard)
export class SalesController {
    constructor(private salesService: SalesService) { }

    @Post()
    @Roles('ADMIN', 'CASHIER', 'SUPERVISOR')
    createSale(@Body() createSaleDto: CreateSaleDto, @Request() req) {
        return this.salesService.createSale(createSaleDto, req.user.id);
    }

    @Get()
    getSales(
        @Query('startDate') startDate?: string,
        @Query('endDate') endDate?: string,
        @Query('userId') userId?: string,
        @Query('status') status?: string,
    ) {
        const filters: any = {};

        if (startDate) filters.startDate = new Date(startDate);
        if (endDate) filters.endDate = new Date(endDate);
        if (userId) filters.userId = parseInt(userId);
        if (status) filters.status = status;

        return this.salesService.getSales(filters);
    }

    @Get(':id')
    getSaleById(@Param('id') id: string) {
        return this.salesService.getSaleById(parseInt(id));
    }

    @Put(':id/cancel')
    @Roles('ADMIN', 'SUPERVISOR')
    cancelSale(@Param('id') id: string) {
        return this.salesService.cancelSale(parseInt(id));
    }
}
