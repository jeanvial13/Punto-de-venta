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
import { CashRegisterService } from './cash-register.service';
import {
    OpenRegisterDto,
    CloseRegisterDto,
    CreateCashMovementDto,
} from './dto/cash-register.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('cash-register')
@UseGuards(JwtAuthGuard, RolesGuard)
export class CashRegisterController {
    constructor(private cashRegisterService: CashRegisterService) { }

    @Post('open')
    @Roles('ADMIN', 'CASHIER', 'SUPERVISOR')
    openRegister(@Body() openRegisterDto: OpenRegisterDto, @Request() req) {
        return this.cashRegisterService.openRegister(openRegisterDto, req.user.id);
    }

    @Put(':id/close')
    @Roles('ADMIN', 'CASHIER', 'SUPERVISOR')
    closeRegister(@Param('id') id: string, @Body() closeRegisterDto: CloseRegisterDto) {
        return this.cashRegisterService.closeRegister(parseInt(id), closeRegisterDto);
    }

    @Post('movements')
    @Roles('ADMIN', 'CASHIER', 'SUPERVISOR')
    createCashMovement(@Body() createCashMovementDto: CreateCashMovementDto) {
        return this.cashRegisterService.createCashMovement(createCashMovementDto);
    }

    @Get('current')
    @Roles('ADMIN', 'CASHIER', 'SUPERVISOR')
    getCurrentRegister(@Request() req) {
        return this.cashRegisterService.getCurrentRegister(req.user.id);
    }

    @Get('history')
    @Roles('ADMIN', 'SUPERVISOR')
    getRegisterHistory(@Query('userId') userId?: string) {
        const userIdNum = userId ? parseInt(userId) : undefined;
        return this.cashRegisterService.getRegisterHistory(userIdNum);
    }
}
