import { IsNumber, IsString, IsOptional, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

class SaleItemDto {
    @IsNumber()
    productId: number;

    @IsNumber()
    quantity: number;

    @IsNumber()
    price: number;
}

export class CreateSaleDto {
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => SaleItemDto)
    items: SaleItemDto[];

    @IsOptional()
    @IsNumber()
    clientId?: number;

    @IsString()
    paymentMethod: string; // CASH, CARD, TRANSFER, MIXED

    @IsOptional()
    @IsNumber()
    discount?: number;
}
