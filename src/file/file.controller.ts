import {
  BadRequestException,
  Controller,
  Get,
  Query,
  Res,
  Logger,
  HttpStatus,
} from '@nestjs/common';
import { ApiQuery, ApiOperation, ApiTags, ApiOkResponse, ApiNotFoundResponse } from '@nestjs/swagger';
import { FastifyReply } from 'fastify';
import { FileService } from './file.service';

@Controller('/api/file')
@ApiTags('Files controller')
export class FileController {
  private readonly logger = new Logger(FileController.name);

  constructor(private fileService: FileService) {}

  @Get('raw')
  @ApiQuery({
    name: 'path',
    example: 'config/products/crystals/amethyst.jpg',
    required: true,
  })
  @ApiOperation({
    description: 'Reads a file from the server.',
  })
  @ApiNotFoundResponse({
    description: 'File not found.',
  })
  @ApiOkResponse({
    description: 'Returns the requested file.',
  })
  async readFile(
    @Query('path') file: string,
    @Res({ passthrough: true }) res: FastifyReply,
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
}