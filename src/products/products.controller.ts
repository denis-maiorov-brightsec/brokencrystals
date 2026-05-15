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
  @ApiOperation({
    description: 'Retrieve the latest products with an optional limit on the number of results.'
  })
  @ApiOkResponse({
    type: ProductDto,
    isArray: true
  })
  async getLatestProducts(
    @Query('limit') limit: number
  ): Promise<ProductDto[]> {
    this.logger.debug('Get latest products.');

    // Validate and enforce limit constraints
    const maxLimit = 10;
    if (limit === undefined || limit === null) {
      limit = 3; // Default limit
    } else if (isNaN(limit) || limit <= 0 || limit > maxLimit) {
      throw new BadRequestException(`Limit must be a positive number not exceeding ${maxLimit}`);
    }

    const products = await this.productsService.findLatest(limit);
    return products.map((p) => new ProductDto(p));
  }
}