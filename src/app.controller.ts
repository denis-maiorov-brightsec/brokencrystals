import { Controller, Get, Logger } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AppService } from './app.service';
import { AppConfig } from './app.config.api';

@Controller('/api')
@ApiTags('App controller')
export class AppController {
  private readonly logger = new Logger(AppController.name);

  constructor(private readonly appService: AppService) {}

  @Get('/config')
  @ApiOperation({
    description: 'Provides limited configuration details for public access.'
  })
  getConfig(): Partial<AppConfig> {
    this.logger.warn('Public access to configuration endpoint.');
    return this.appService.getConfig();
  }
}