import { IsString, IsOptional, IsNumber, IsBoolean } from 'class-validator';

export class CreateProductDto {
    @IsString()
    name: string;

    @IsOptional()
    @IsString()
    barcode?: string;

    @IsOptional()
    @IsString()
    sku?: string;

    @IsOptional()
    @IsString()
    description?: string;

    @IsNumber()
    price: number;

    @IsNumber()
    cost: number;

    @IsOptional()
    @IsNumber()
    tax?: number;

    @IsOptional()
    @IsNumber()
    stock?: number;

    @IsOptional()
    @IsNumber()
    minStock?: number;

    @IsOptional()
    @IsString()
    image?: string;

    @IsOptional()
    @IsBoolean()
    status?: boolean;

    @IsOptional()
    @IsNumber()
    categoryId?: number;
}

export class UpdateProductDto {
    @IsOptional()
    @IsString()
    name?: string;

    @IsOptional()
    @IsString()
    barcode?: string;

    @IsOptional()
    @IsString()
    sku?: string;

    @IsOptional()
    @IsString()
    description?: string;

    @IsOptional()
    @IsNumber()
    price?: number;

    @IsOptional()
    @IsNumber()
    cost?: number;

    @IsOptional()
    @IsNumber()
    tax?: number;

    @IsOptional()
    @IsNumber()
    stock?: number;

    @IsOptional()
    @IsNumber()
    minStock?: number;

    @IsOptional()
    @IsString()
    image?: string;

    @IsOptional()
    @IsBoolean()
    status?: boolean;

    @IsOptional()
    @IsNumber()
    categoryId?: number;
}
