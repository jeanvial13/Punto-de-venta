import { IsNumber, IsString, IsOptional } from 'class-validator';

export class OpenRegisterDto {
    @IsNumber()
    startAmount: number;
}

export class CloseRegisterDto {
    @IsNumber()
    endAmount: number;
}

export class CreateCashMovementDto {
    @IsNumber()
    cashRegisterId: number;

    @IsString()
    type: string; // IN, OUT

    @IsNumber()
    amount: number;

    @IsOptional()
    @IsString()
    reason?: string;
}
