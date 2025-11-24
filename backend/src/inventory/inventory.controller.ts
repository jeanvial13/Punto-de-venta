import {
    Controller,
    Get,
    Post,
    Body,
    Param,
    Query,
    UseGuards,
    Request,
} from '@nestjs/common';
import { InventoryService } from './inventory.service';
import { CreateInventoryLogDto } from './dto/inventory.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('inventory')
@UseGuards(JwtAuthGuard, RolesGuard)
export class InventoryController {
    constructor(private inventoryService: InventoryService) { }

    @Post('logs')
    @Roles('ADMIN', 'INVENTORY')
    createInventoryLog(@Body() createInventoryLogDto: CreateInventoryLogDto, @Request() req) {
        return this.inventoryService.createInventoryLog(createInventoryLogDto, req.user.id);
    }

    @Get('logs')
    @Roles('ADMIN', 'INVENTORY')
    getInventoryLogs(@Query('productId') productId?: string, @Query('type') type?: string) {
        const filters: any = {};
        if (productId) filters.productId = parseInt(productId);
        if (type) filters.type = type;

        return this.inventoryService.getInventoryLogs(filters);
    }

    @Get('kardex/:productId')
    @Roles('ADMIN', 'INVENTORY')
    getKardex(@Param('productId') productId: string) {
        return this.inventoryService.getKardex(parseInt(productId));
    }
}
