import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppConfig } from './app.config.api';

@Injectable()
export class AppService {
  private readonly logger = new Logger(AppService.name);

  constructor(private readonly configService: ConfigService) {}

  getConfig(): Partial<AppConfig> {
    this.logger.warn('Access to configuration endpoint detected.');

    return {
      awsBucket: this.configService.get<string>('AWS_BUCKET') || 'Not Available',
    };
  }
}