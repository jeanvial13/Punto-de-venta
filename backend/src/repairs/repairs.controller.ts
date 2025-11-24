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
    Delete,
} from '@nestjs/common';
import { RepairsService } from './repairs.service';
import {
    CreateRepairDto,
    UpdateRepairDto,
    AddRepairItemDto,
    AddSoftwareActionDto,
    ChangeStatusDto,
    AddRepairNoteDto,
    DeliverRepairDto,
} from './dto/repair.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('repairs')
@UseGuards(JwtAuthGuard, RolesGuard)
export class RepairsController {
    constructor(private repairsService: RepairsService) { }

    @Post()
    @Roles('ADMIN', 'SUPERVISOR', 'CASHIER')
    createRepair(@Body() createRepairDto: CreateRepairDto, @Request() req) {
        return this.repairsService.createRepair(createRepairDto, req.user.id);
    }

    @Get()
    findAllRepairs(
        @Query('status') status?: string,
        @Query('technicianId') technicianId?: string,
        @Query('clientId') clientId?: string,
        @Query('startDate') startDate?: string,
        @Query('endDate') endDate?: string,
    ) {
        const filters: any = {};

        if (status) filters.status = status;
        if (technicianId) filters.technicianId = parseInt(technicianId);
        if (clientId) filters.clientId = parseInt(clientId);
        if (startDate) filters.startDate = new Date(startDate);
        if (endDate) filters.endDate = new Date(endDate);

        return this.repairsService.findAllRepairs(filters);
    }

    @Get('history')
    getRepairHistory(@Query('deviceId') deviceId?: string, @Query('clientId') clientId?: string) {
        const deviceIdNum = deviceId ? parseInt(deviceId) : undefined;
        const clientIdNum = clientId ? parseInt(clientId) : undefined;

        return this.repairsService.getRepairHistory(deviceIdNum, clientIdNum);
    }

    @Get(':id')
    findRepairById(@Param('id') id: string) {
        return this.repairsService.findRepairById(parseInt(id));
    }

    @Put(':id')
    @Roles('ADMIN', 'SUPERVISOR')
    updateRepair(@Param('id') id: string, @Body() updateRepairDto: UpdateRepairDto) {
        return this.repairsService.updateRepair(parseInt(id), updateRepairDto);
    }

    @Put(':id/status')
    changeStatus(@Param('id') id: string, @Body() changeStatusDto: ChangeStatusDto, @Request() req) {
        return this.repairsService.changeStatus(parseInt(id), changeStatusDto, req.user.id);
    }

    @Post(':id/items')
    @Roles('ADMIN', 'SUPERVISOR')
    addRepairItem(@Param('id') id: string, @Body() addRepairItemDto: AddRepairItemDto) {
        return this.repairsService.addRepairItem(parseInt(id), addRepairItemDto);
    }

    @Post(':id/software')
    @Roles('ADMIN', 'SUPERVISOR')
    addSoftwareAction(@Param('id') id: string, @Body() addSoftwareActionDto: AddSoftwareActionDto) {
        return this.repairsService.addSoftwareAction(parseInt(id), addSoftwareActionDto);
    }

    @Post(':id/notes')
    addNote(@Param('id') id: string, @Body() addRepairNoteDto: AddRepairNoteDto, @Request() req) {
        return this.repairsService.addNote(parseInt(id), addRepairNoteDto, req.user.id);
    }

    @Post(':id/deliver')
    @Roles('ADMIN', 'SUPERVISOR')
    deliverRepair(@Param('id') id: string, @Body() deliverRepairDto: DeliverRepairDto, @Request() req) {
        return this.repairsService.deliverRepair(parseInt(id), deliverRepairDto, req.user.id);
    }

    @Delete(':id')
    @Roles('ADMIN', 'SUPERVISOR')
    cancelRepair(@Param('id') id: string, @Request() req) {
        return this.repairsService.cancelRepair(parseInt(id), req.user.id);
    }
}
