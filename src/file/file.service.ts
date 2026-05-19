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

    if (file.startsWith('http')) {
      const content = await this.cloudProviders.get(file);

      if (content) {
        return Readable.from(content);
      } else {
        throw new Error(`no such file or directory, access '${file}'`);
      }
    } else {
      const appRoot = path.resolve(process.cwd());

      if (path.isAbsolute(file)) {
        throw new Error('cannot read file from this location');
      }

      const resolvedFile = path.resolve(appRoot, file);
      const relativeToRoot = path.relative(appRoot, resolvedFile);

      if (
        relativeToRoot.startsWith('..') ||
        path.isAbsolute(relativeToRoot)
      ) {
        throw new Error('cannot read file from this location');
      }

      await fs.promises.access(resolvedFile, R_OK);

      return fs.createReadStream(resolvedFile);
    }
  }

  async deleteFile(file: string): Promise<boolean> {
    if (file.startsWith('/')) {
      throw new Error('cannot delete file from this location');
    } else if (file.startsWith('http')) {
      throw new Error('cannot delete file from this location');
    } else {
      file = path.resolve(process.cwd(), file);

      try {
        await fs.promises.unlink(file);
        return true;
      } catch (err) {
        this.logger.error(err.message);
        throw new Error('failed to delete file');
      }
    }
  }
}