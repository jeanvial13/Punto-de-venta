import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ReportsService } from './reports.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('reports')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ReportsController {
    constructor(private reportsService: ReportsService) { }

    @Get('dashboard')
    getDashboardKPIs() {
        return this.reportsService.getDashboardKPIs();
    }

    @Get('sales-by-period')
    @Roles('ADMIN', 'SUPERVISOR')
    getSalesByPeriod(@Query('startDate') startDate: string, @Query('endDate') endDate: string) {
        return this.reportsService.getSalesByPeriod(new Date(startDate), new Date(endDate));
    }

    @Get('top-products')
    @Roles('ADMIN', 'SUPERVISOR')
    getTopProducts(@Query('limit') limit?: string) {
        const limitNum = limit ? parseInt(limit) : 10;
        return this.reportsService.getTopProducts(limitNum);
    }

    @Get('sales-by-category')
    @Roles('ADMIN', 'SUPERVISOR')
    getSalesByCategory() {
        return this.reportsService.getSalesByCategory();
    }

    @Get('inventory-valuation')
    @Roles('ADMIN', 'INVENTORY')
    getInventoryValuation() {
        return this.reportsService.getInventoryValuation();
    }
}
