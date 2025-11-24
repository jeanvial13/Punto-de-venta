import { IsString, IsOptional, IsEmail } from 'class-validator';

export class CreateClientDto {
    @IsString()
    name: string;

    @IsOptional()
    @IsEmail()
    email?: string;

    @IsOptional()
    @IsString()
    phone?: string;

    @IsOptional()
    @IsString()
    address?: string;

    @IsOptional()
    @IsString()
    taxId?: string;

    @IsOptional()
    @IsString()
    notes?: string;
}

export class UpdateClientDto {
    @IsOptional()
    @IsString()
    name?: string;

    @IsOptional()
    @IsEmail()
    email?: string;

    @IsOptional()
    @IsString()
    phone?: string;

    @IsOptional()
    @IsString()
    address?: string;

    @IsOptional()
    @IsString()
    taxId?: string;

    @IsOptional()
    @IsString()
    notes?: string;
}

export class CreateSupplierDto {
    @IsString()
    name: string;

    @IsOptional()
    @IsString()
    contact?: string;

    @IsOptional()
    @IsEmail()
    email?: string;

    @IsOptional()
    @IsString()
    phone?: string;

    @IsOptional()
    @IsString()
    address?: string;
}

export class UpdateSupplierDto {
    @IsOptional()
    @IsString()
    name?: string;

    @IsOptional()
    @IsString()
    contact?: string;

    @IsOptional()
    @IsEmail()
    email?: string;

    @IsOptional()
    @IsString()
    phone?: string;

    @IsOptional()
    @IsString()
    address?: string;
}
