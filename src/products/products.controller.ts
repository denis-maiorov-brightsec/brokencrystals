import { Controller, Get, Query, Logger, BadRequestException } from '@nestjs/common';
import { ApiOperation, ApiOkResponse, ApiQuery, ApiTags } from '@nestjs/swagger';
import { ProductDto } from './api/ProductDto';
import { ProductsService } from './products.service';

@Controller('/api/products')
@ApiTags('Products controller')
export class ProductsController {
  private readonly logger = new Logger(ProductsController.name);

  constructor(private readonly productsService: ProductsService) {}

  @Get('latest')
  @ApiQuery({ name: 'limit', example: 3, required: false })
  @ApiOperation({ description: 'Retrieve the latest products with an optional limit.' })
  @ApiOkResponse({ type: ProductDto, isArray: true })
  async getLatestProducts(@Query('limit') limit: string): Promise<ProductDto[]> {
    this.logger.debug('Get latest products.');

    const maxLimit = 10; // Define a strict maximum limit
    let parsedLimit = parseInt(limit, 10);

    if (isNaN(parsedLimit) || parsedLimit <= 0) {
      parsedLimit = 3; // Default limit if invalid
    }

    if (parsedLimit > maxLimit) {
      parsedLimit = maxLimit; // Enforce maximum limit
    }

    const products = await this.productsService.findLatest(parsedLimit);
    return products.map((p) => new ProductDto(p));
  }
}