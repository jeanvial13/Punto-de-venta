import { IsString, IsNumber, IsOptional, IsBoolean, IsArray } from 'class-validator';

export class CreateDeviceDto {
    @IsNumber()
    clientId: number;

    @IsString()
    brand: string;

    @IsString()
    model: string;

    @IsOptional()
    @IsString()
    color?: string;

    @IsString()
    imei: string;

    @IsString()
    condition: string;

    @IsOptional()
    @IsNumber()
    batteryLevel?: number;

    @IsOptional()
    @IsString()
    accessories?: string;
}

export class CreateRepairDto {
    @IsNumber()
    clientId: number;

    @IsNumber()
    deviceId: number;

    @IsOptional()
    @IsNumber()
    technicianId?: number;

    @IsString()
    reportedIssue: string;

    @IsOptional()
    @IsString()
    diagnosticInitial?: string;

    @IsNumber()
    estimatedCost: number;

    @IsOptional()
    @IsString()
    estimatedDelivery?: string;

    @IsOptional()
    @IsString()
    warranty?: string;
}

export class UpdateRepairDto {
    @IsOptional()
    @IsNumber()
    technicianId?: number;

    @IsOptional()
    @IsString()
    diagnosticInitial?: string;

    @IsOptional()
    @IsString()
    diagnosticFinal?: string;

    @IsOptional()
    @IsNumber()
    estimatedCost?: number;

    @IsOptional()
    @IsNumber()
    finalCost?: number;

    @IsOptional()
    @IsString()
    estimatedDelivery?: string;

    @IsOptional()
    @IsString()
    warranty?: string;

    @IsOptional()
    @IsString()
    status?: string;
}

export class AddRepairItemDto {
    @IsNumber()
    productId: number;

    @IsNumber()
    quantity: number;

    @IsNumber()
    cost: number;

    @IsOptional()
    @IsString()
    warranty?: string;
}

export class AddSoftwareActionDto {
    @IsString()
    serviceType: string;

    @IsNumber()
    cost: number;

    @IsOptional()
    @IsString()
    notes?: string;

    @IsOptional()
    @IsBoolean()
    legalAuthorization?: boolean;
}

export class ChangeStatusDto {
    @IsString()
    status: string;

    @IsOptional()
    @IsString()
    notes?: string;
}

export class AddRepairNoteDto {
    @IsString()
    content: string;

    @IsBoolean()
    isInternal: boolean;
}

export class DeliverRepairDto {
    @IsNumber()
    finalCost: number;

    @IsOptional()
    @IsString()
    signaturePhoto?: string;
}
