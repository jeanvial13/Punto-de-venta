import { Controller, Get, Post, Put, Body, Param, Query, UseGuards } from '@nestjs/common';
import { TechniciansService } from './technicians.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('technicians')
@UseGuards(JwtAuthGuard, RolesGuard)
export class TechniciansController {
    constructor(private techniciansService: TechniciansService) { }

    @Post()
    @Roles('ADMIN')
    createTechnician(@Body() body: { userId: number; specializations: string[] }) {
        return this.techniciansService.createTechnician(body.userId, body.specializations);
    }

    @Get()
    findAllTechnicians(@Query('activeOnly') activeOnly?: string) {
        const active = activeOnly === 'false' ? false : true;
        return this.techniciansService.findAllTechnicians(active);
    }

    @Get(':id')
    findTechnicianById(@Param('id') id: string) {
        return this.techniciansService.findTechnicianById(parseInt(id));
    }

    @Get(':id/repairs')
    getAssignedRepairs(@Param('id') id: string) {
        return this.techniciansService.getAssignedRepairs(parseInt(id));
    }

    @Get(':id/pending')
    getPendingTasks(@Param('id') id: string) {
        return this.techniciansService.getPendingTasks(parseInt(id));
    }

    @Put(':id')
    @Roles('ADMIN')
    updateTechnician(
        @Param('id') id: string,
        @Body() body: { specializations?: string[]; isActive?: boolean },
    ) {
        return this.techniciansService.updateTechnician(parseInt(id), body);
    }
}
