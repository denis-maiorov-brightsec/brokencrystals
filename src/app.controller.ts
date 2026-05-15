import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  Header,
  HttpException,
  InternalServerErrorException,
  Logger,
  Options,
  Param,
  Post,
  Query,
  Redirect,
  SerializeOptions,
  UseGuards,
  UseInterceptors,
  ParseIntPipe,
  DefaultValuePipe,
  HttpStatus
} from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import {
  ApiBody,
  ApiConsumes,
  ApiCreatedResponse,
  ApiInternalServerErrorResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiProduces,
  ApiQuery,
  ApiTags
} from '@nestjs/swagger';
import * as dotT from 'dot';
import { parseXml } from 'libxmljs';
import { AppConfig } from './app.config.api';
import {
  API_DESC_CONFIG_SERVER,
  API_DESC_LAUNCH_COMMAND,
  API_DESC_OPTIONS_REQUEST,
  API_DESC_REDIRECT_REQUEST,
  API_DESC_RENDER_REQUEST,
  API_DESC_XML_METADATA,
  SWAGGER_DESC_SECRETS,
  SWAGGER_DESC_NESTED_JSON
} from './app.controller.swagger.desc';
import { AuthGuard } from './auth/auth.guard';
import { JwtType } from './auth/jwt/jwt.type.decorator';
import { JwtProcessorType } from './auth/auth.service';
import { AppService } from './app.service';
import { BASIC_USER_INFO, UserDto } from './users/api/UserDto';
import { SWAGGER_DESC_FIND_USER } from './users/users.controller.swagger.desc';
import { DOMParser } from '@xmldom/xmldom';

@Controller('/api')
@ApiTags('App controller')
export class AppController {
  private readonly logger = new Logger(AppController.name);

  constructor(private readonly appService: AppService) {}

  @Get('/config')
  @ApiOperation({
    description: API_DESC_CONFIG_SERVER
  })
  @ApiOkResponse({
    type: AppConfig
  })
  getConfig(): AppConfig {
    const config = this.appService.getConfig();
    return {
      awsBucket: config.awsBucket,
      sql: 'REDACTED',
      googlemaps: 'REDACTED'
    };
  }

  @Post('/metadata')
  @ApiOperation({
    description: API_DESC_XML_METADATA
  })
  @ApiConsumes('application/xml')
  @ApiCreatedResponse({
    description: 'Metadata processed successfully.'
  })
  processMetadata(@Body() xmlData: string): string {
    try {
      const parser = new DOMParser({
        locator: {},
        errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} }
      });
      const xmlDoc = parser.parseFromString(xmlData, 'text/xml');

      if (xmlDoc.getElementsByTagName('parsererror').length > 0) {
        throw new Error('Invalid XML format.');
      }

      // Process the XML document as needed
      return 'Metadata processed successfully.';
    } catch (error) {
      this.logger.error('Error processing metadata:', error);
      throw new HttpException('Failed to process metadata.', HttpStatus.BAD_REQUEST);
    }
  }

  @Get('/secrets')
  @ApiOperation({
    description: SWAGGER_DESC_SECRETS
  })
  @ApiOkResponse({
    type: Object
  })
  getSecrets(): Record<string, string> {
    this.logger.warn('Access to secrets endpoint is deprecated and restricted.');
    throw new HttpException('Access to this endpoint is forbidden.', HttpStatus.FORBIDDEN);
  }

  // Other methods remain unchanged
}