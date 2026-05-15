import { Injectable, Logger } from '@nestjs/common';
import { Readable } from 'stream';
import * as fs from 'fs';
import * as path from 'path';
import { CloudProvidersMetaData } from './cloud.providers.metadata';
import { R_OK } from 'constants';

@Injectable()
export class FileService {
  private readonly logger = new Logger(FileService.name);
  private cloudProviders = new CloudProvidersMetaData();

  async getFile(file: string): Promise<Readable> {
    this.logger.log(`Reading file: ${file}`);

    try {
      // Define an allowlist of directories
      const allowedDirectories = [
        path.resolve(process.cwd(), 'public'),
        path.resolve(process.cwd(), 'uploads'),
      ];

      // Resolve and normalize the requested file path
      const sanitizedPath = path.resolve(process.cwd(), file);

      // Check if the resolved path is within the allowed directories
      const isAllowed = allowedDirectories.some((dir) => sanitizedPath.startsWith(dir));
      if (!isAllowed) {
        throw new Error('Access to the specified file path is not allowed');
      }

      // Check if the file exists and is readable
      await fs.promises.access(sanitizedPath, R_OK);

      // Return the file as a readable stream
      return fs.createReadStream(sanitizedPath);
    } catch (error) {
      this.logger.error(`Error accessing file: ${error.message}`);
      throw new Error('An error occurred while accessing the file.');
    }
  }

  async deleteFile(file: string): Promise<boolean> {
    try {
      // Define an allowlist of directories
      const allowedDirectories = [
        path.resolve(process.cwd(), 'uploads'),
      ];

      // Resolve and normalize the requested file path
      const sanitizedPath = path.resolve(process.cwd(), file);

      // Check if the resolved path is within the allowed directories
      const isAllowed = allowedDirectories.some((dir) => sanitizedPath.startsWith(dir));
      if (!isAllowed) {
        throw new Error('Access to the specified file path is not allowed');
      }

      // Delete the file
      await fs.promises.unlink(sanitizedPath);
      return true;
    } catch (error) {
      this.logger.error(`Error deleting file: ${error.message}`);
      throw new Error('An error occurred while deleting the file.');
    }
  }
}