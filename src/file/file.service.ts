import { Injectable, Logger } from '@nestjs/common';
import { Readable } from 'stream';
import * as fs from 'fs';
import * as path from 'path';
import { CloudProvidersMetaData } from './cloud.providers.metadata';
import { R_OK } from 'constants';
import * as url from 'url';

@Injectable()
export class FileService {
  private readonly logger = new Logger(FileService.name);
  private cloudProviders = new CloudProvidersMetaData();

  async getFile(file: string): Promise<Readable> {
    this.logger.log(`Reading file: ${file}`);

    try {
      if (file.startsWith('/')) {
        const sanitizedPath = path.normalize(file);
        if (!sanitizedPath.startsWith('/')) {
          throw new Error('Invalid file path');
        }
        await fs.promises.access(sanitizedPath, R_OK);

        return fs.createReadStream(sanitizedPath);
      } else if (file.startsWith('http')) {
        throw new Error('Remote file access is not allowed');
      } else {
        const sanitizedPath = path.resolve(process.cwd(), file);
        if (!sanitizedPath.startsWith(process.cwd())) {
          throw new Error('Invalid file path');
        }
        await fs.promises.access(sanitizedPath, R_OK);

        return fs.createReadStream(sanitizedPath);
      }
    } catch (error) {
      this.logger.error(`Error accessing file: ${error.message}`);
      throw new Error('An error occurred while accessing the file.');
    }
  }

  async deleteFile(file: string): Promise<boolean> {
    if (file.startsWith('/')) {
      throw new Error('cannot delete file from this location');
    } else if (file.startsWith('http')) {
      throw new Error('cannot delete file from this location');
    } else {
      const sanitizedPath = path.resolve(process.cwd(), file);
      if (!sanitizedPath.startsWith(process.cwd())) {
        throw new Error('Invalid file path');
      }
      await fs.promises.unlink(sanitizedPath);
      return true;
    }
  }
}