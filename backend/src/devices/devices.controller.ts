import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { DevicesService } from './devices.service';
import { CreateDeviceDto } from '../repairs/dto/repair.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('devices')
@UseGuards(JwtAuthGuard)
export class DevicesController {
    constructor(private devicesService: DevicesService) { }

    @Post()
    createDevice(@Body() createDeviceDto: CreateDeviceDto) {
        return this.devicesService.createDevice(createDeviceDto);
    }

    @Get(':id')
    findDeviceById(@Param('id') id: string) {
        return this.devicesService.findDeviceById(parseInt(id));
    }

    @Get('imei/:imei')
    findDeviceByIMEI(@Param('imei') imei: string) {
        return this.devicesService.findDeviceByIMEI(imei);
    }

    @Get(':id/history')
    getDeviceRepairHistory(@Param('id') id: string) {
        return this.devicesService.getDeviceRepairHistory(parseInt(id));
    }

    @Post(':id/photos')
    uploadDevicePhoto(
        @Param('id') id: string,
        @Body() body: { photoUrl: string; photoType: string },
    ) {
        return this.devicesService.uploadDevicePhoto(parseInt(id), body.photoUrl, body.photoType);
    }
}
