import { IsNumber, IsString, IsOptional } from 'class-validator';

export class CreateInventoryLogDto {
    @IsNumber()
    productId: number;

    @IsString()
    type: string; // IN, OUT, ADJUSTMENT

    @IsNumber()
    quantity: number;

    @IsOptional()
    @IsString()
    reason?: string;
}
