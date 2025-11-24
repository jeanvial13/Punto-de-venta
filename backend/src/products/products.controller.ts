import {
    Controller,
    Get,
    Post,
    Put,
    Delete,
    Body,
    Param,
    Query,
    UseGuards,
} from '@nestjs/common';
import { ProductsService } from './products.service';
import { CreateProductDto, UpdateProductDto } from './dto/product.dto';
import { CreateCategoryDto, UpdateCategoryDto } from './dto/category.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('products')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ProductsController {
    constructor(private productsService: ProductsService) { }

    @Post()
    @Roles('ADMIN', 'INVENTORY')
    createProduct(@Body() createProductDto: CreateProductDto) {
        return this.productsService.createProduct(createProductDto);
    }

    @Get()
    findAllProducts(
        @Query('categoryId') categoryId?: string,
        @Query('status') status?: string,
        @Query('search') search?: string,
    ) {
        const filters: any = {};
        if (categoryId) filters.categoryId = parseInt(categoryId);
        if (status) filters.status = status === 'true';
        if (search) filters.search = search;

        return this.productsService.findAllProducts(filters);
    }

    @Get('low-stock')
    @Roles('ADMIN', 'INVENTORY')
    getLowStockProducts() {
        return this.productsService.getLowStockProducts();
    }

    @Get(':id')
    findProductById(@Param('id') id: string) {
        return this.productsService.findProductById(parseInt(id));
    }

    @Put(':id')
    @Roles('ADMIN', 'INVENTORY')
    updateProduct(@Param('id') id: string, @Body() updateProductDto: UpdateProductDto) {
        return this.productsService.updateProduct(parseInt(id), updateProductDto);
    }

    @Delete(':id')
    @Roles('ADMIN')
    deleteProduct(@Param('id') id: string) {
        return this.productsService.deleteProduct(parseInt(id));
    }
}

@Controller('categories')
@UseGuards(JwtAuthGuard, RolesGuard)
export class CategoriesController {
    constructor(private productsService: ProductsService) { }

    @Post()
    @Roles('ADMIN', 'INVENTORY')
    createCategory(@Body() createCategoryDto: CreateCategoryDto) {
        return this.productsService.createCategory(createCategoryDto);
    }

    @Get()
    findAllCategories() {
        return this.productsService.findAllCategories();
    }

    @Get(':id')
    findCategoryById(@Param('id') id: string) {
        return this.productsService.findCategoryById(parseInt(id));
    }

    @Put(':id')
    @Roles('ADMIN', 'INVENTORY')
    updateCategory(@Param('id') id: string, @Body() updateCategoryDto: UpdateCategoryDto) {
        return this.productsService.updateCategory(parseInt(id), updateCategoryDto);
    }

    @Delete(':id')
    @Roles('ADMIN')
    deleteCategory(@Param('id') id: string) {
        return this.productsService.deleteCategory(parseInt(id));
    }
}
