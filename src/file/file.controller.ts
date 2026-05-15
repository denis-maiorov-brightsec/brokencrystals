import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpStatus,
  Logger,
  Put,
  Query,
  Res
} from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import {
  ApiHeader,
  ApiInternalServerErrorResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags
} from '@nestjs/swagger';
import { W_OK } from 'constants';
import * as fs from 'fs';
import * as path from 'path';
import { Stream } from 'stream';
import { FileService } from './file.service';
import { FastifyReply } from 'fastify';
import {
  SWAGGER_DESC_DELETE_FILE,
  SWAGGER_DESC_READ_FILE,
  SWAGGER_DESC_READ_FILE_ON_SERVER,
  SWAGGER_DESC_SAVE_RAW_CONTENT
} from './file.controller.swagger.desc';
import { CloudProvidersMetaData } from './cloud.providers.metadata';

@Controller('/api/file')
@ApiTags('Files controller')
export class FileController {
  private readonly logger = new Logger(FileController.name);

  constructor(private fileService: FileService) {}

  private getContentType(contentType: string) {
    if (contentType) {
      return contentType;
    } else {
      return 'application/octet-stream';
    }
  }

  private async loadCPFile(cpBaseUrl: string, path: string) {
    if (!path.startsWith(cpBaseUrl)) {
      throw new BadRequestException(`Invalid parameter 'path'`);
    }

    try {
      const file: Stream = await this.fileService.getFile(path);
      return file;
    } catch (error) {
      this.logger.error(`Error loading file from cloud provider: ${error.message}`);
      throw new BadRequestException('Failed to load file from cloud provider.');
    }
  }

  @Get()
  @ApiQuery({
    name: 'path',
    example: 'config/products/crystals/amethyst.jpg',
    required: true
  })
  @ApiQuery({ name: 'type', example: 'image/jpg', required: true })
  @ApiHeader({ name: 'accept', example: 'image/jpg', required: true })
  @ApiOkResponse({
    description: 'File read successfully'
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      properties: {
        error: { type: 'string' },
        location: { type: 'string' }
      }
    }
  })
  @ApiOperation({
    description: SWAGGER_DESC_READ_FILE
  })
  async loadFile(
    @Query('path') path: string,
    @Query('type') contentType: string,
    @Res({ passthrough: true }) res: FastifyReply
  ) {
    if (!this.isValidPath(path)) {
      throw new BadRequestException('Invalid file path.');
    }

    try {
      const file: Stream = await this.fileService.getFile(path);
      const type = this.getContentType(contentType);
      res.type(type);

      return file;
    } catch (error) {
      this.logger.error(`Error loading file: ${error.message}`);
      throw new BadRequestException('Failed to load file.');
    }
  }

  private isValidPath(path: string): boolean {
    const forbiddenPatterns = [
      /^http:\/\//i,
      /^https:\/\//i,
      /\.{2}/, // Prevent directory traversal
    ];

    return !forbiddenPatterns.some((pattern) => pattern.test(path));
  }

  @Get('/google')
  @ApiQuery({
    name: 'path',
    example: 'config/products/crystals/amethyst.jpg',
    required: true
  })
  @ApiQuery({ name: 'type', example: 'image/jpg', required: true })
  @ApiHeader({ name: 'accept', example: 'image/jpg', required: true })
  @ApiOkResponse({
    description: 'File read successfully'
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      properties: {
        error: { type: 'string' },
        location: { type: 'string' }
      }
    }
  })
  @ApiOperation({
    description: SWAGGER_DESC_READ_FILE
  })
  async loadGoogleFile(
    @Query('path') path: string,
    @Query('type') contentType: string,
    @Res({ passthrough: true }) res: FastifyReply
  ) {
    try {
      const file: Stream = await this.loadCPFile(
        CloudProvidersMetaData.GOOGLE,
        path
      );
      const type = this.getContentType(contentType);
      res.type(type);

      return file;
    } catch (error) {
      this.logger.error(`Error loading Google file: ${error.message}`);
      throw new BadRequestException('Failed to load Google file.');
    }
  }

  @Get('/aws')
  @ApiQuery({
    name: 'path',
    example: 'config/products/crystals/amethyst.jpg',
    required: true
  })
  @ApiQuery({ name: 'type', example: 'image/jpg', required: true })
  @ApiHeader({ name: 'accept', example: 'image/jpg', required: true })
  @ApiOkResponse({
    description: 'File read successfully'
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      properties: {
        error: { type: 'string' },
        location: { type: 'string' }
      }
    }
  })
  @ApiOperation({
    description: SWAGGER_DESC_READ_FILE
  })
  async loadAwsFile(
    @Query('path') path: string,
    @Query('type') contentType: string,
    @Res({ passthrough: true }) res: FastifyReply
  ) {
    try {
      const file: Stream = await this.loadCPFile(
        CloudProvidersMetaData.AWS,
        path
      );
      const type = this.getContentType(contentType);
      res.type(type);

      return file;
    } catch (error) {
      this.logger.error(`Error loading AWS file: ${error.message}`);
      throw new BadRequestException('Failed to load AWS file.');
    }
  }

  @Get('/azure')
  @ApiQuery({
    name: 'path',
    example: 'config/products/crystals/amethyst.jpg',
    required: true
  })
  @ApiQuery({ name: 'type', example: 'image/jpg', required: true })
  @ApiHeader({ name: 'accept', example: 'image/jpg', required: true })
  @ApiOkResponse({
    description: 'File read successfully'
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      properties: {
        error: { type: 'string' },
        location: { type: 'string' }
      }
    }
  })
  @ApiOperation({
    description: SWAGGER_DESC_READ_FILE
  })
  async loadAzureFile(
    @Query('path') path: string,
    @Query('type') contentType: string,
    @Res({ passthrough: true }) res: FastifyReply
  ) {
    try {
      const file: Stream = await this.loadCPFile(
        CloudProvidersMetaData.AZURE,
        path
      );
      const type = this.getContentType(contentType);
      res.type(type);

      return file;
    } catch (error) {
      this.logger.error(`Error loading Azure file: ${error.message}`);
      throw new BadRequestException('Failed to load Azure file.');
    }
  }

  @Get('/digital_ocean')
  @ApiQuery({
    name: 'path',
    example: 'config/products/crystals/amethyst.jpg',
    required: true
  })
  @ApiQuery({ name: 'type', example: 'image/jpg', required: true })
  @ApiHeader({ name: 'accept', example: 'image/jpg', required: true })
  @ApiOkResponse({
    description: 'File read successfully'
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      properties: {
        error: { type: 'string' },
        location: { type: 'string' }
      }
    }
  })
  @ApiOperation({
    description: SWAGGER_DESC_READ_FILE
  })
  async loadDigitalOceanFile(
    @Query('path') path: string,
    @Query('type') contentType: string,
    @Res({ passthrough: true }) res: FastifyReply
  ) {
    try {
      const file: Stream = await this.loadCPFile(
        CloudProvidersMetaData.DIGITAL_OCEAN,
        path
      );
      const type = this.getContentType(contentType);
      res.type(type);

      return file;
    } catch (error) {
      this.logger.error(`Error loading Digital Ocean file: ${error.message}`);
      throw new BadRequestException('Failed to load Digital Ocean file.');
    }
  }

  @Delete()
  @ApiQuery({
    name: 'path',
    example: 'config/products/crystals/some_file.jpg',
    required: true
  })
  @ApiOperation({
    description: SWAGGER_DESC_DELETE_FILE
  })
  @ApiInternalServerErrorResponse({
    schema: {
      type: 'object',
      properties: {
        error: { type: 'string' },
        location: { type: 'string' }
      }
    }
  })
  @ApiOkResponse({
    description: 'File deleted successfully'
  })
  async deleteFile(@Query('path') path: string): Promise<void> {
    try {
      await this.fileService.deleteFile(path);
    } catch (error) {
      this.logger.error(`Error deleting file: ${error.message}`);
      throw new BadRequestException('Failed to delete file.');
    }
  }

  @Put('raw')
  @ApiQuery({
    name: 'path',
    example: 'some/path/to/file.png',
    required: true
  })
  @ApiOperation({
    description: SWAGGER_DESC_SAVE_RAW_CONTENT
  })
  @ApiOkResponse()
  async uploadFile(
    @Query('path') file: string,
    @Body() raw: string
  ): Promise<string> {
    try {
      if (typeof raw === 'string' || Buffer.isBuffer(raw)) {
        await fs.promises.access(path.dirname(file), W_OK);
        await fs.promises.writeFile(file, raw);
        return `File uploaded successfully at ${file}`;
      }
    } catch (err) {
      this.logger.error(`Error uploading file: ${err.message}`);
      throw new BadRequestException('Failed to upload file.');
    }
  }

  @Get('raw')
  @ApiQuery({
    name: 'path',
    example: 'config/products/crystals/amethyst.jpg',
    required: true
  })
  @ApiOperation({
    description: SWAGGER_DESC_READ_FILE_ON_SERVER
  })
  @ApiNotFoundResponse({
    description: 'File not found'
  })
  @ApiOkResponse({
    description: 'Returns requested file'
  })
  async readFile(
    @Query('path') file: string,
    @Res({ passthrough: true }) res: FastifyReply
  ) {
    try {
      const stream = await this.fileService.getFile(file);
      res.type('application/octet-stream');

      return stream;
    } catch (err) {
      this.logger.error(`Error reading file: ${err.message}`);
      res.status(HttpStatus.NOT_FOUND);
      throw new BadRequestException('File not found.');
    }
  }

  @GrpcMethod('FileService', 'ReadFile')
  async readFileGrpc(data: { path: string }): Promise<{ content: string }> {
    try {
      const stream = await this.fileService.getFile(data.path);
      const chunks = [];
      for await (const chunk of stream) {
        chunks.push(Buffer.from(chunk));
      }
      return { content: Buffer.concat(chunks).toString('utf-8') };
    } catch (error) {
      this.logger.error(`Error reading file via gRPC: ${error.message}`);
      throw new BadRequestException('Failed to read file via gRPC.');
    }
  }
}