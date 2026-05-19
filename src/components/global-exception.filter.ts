import {
  ArgumentsHost,
  Catch,
  HttpException,
  InternalServerErrorException,
  Logger
} from '@nestjs/common';
import { BaseExceptionFilter } from '@nestjs/core';
import { GqlContextType } from '@nestjs/graphql';

@Catch()
export class GlobalExceptionFilter extends BaseExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  public catch(exception: unknown, host: ArgumentsHost) {
    const gql = host.getType<GqlContextType>() === 'graphql';

    if (exception instanceof HttpException) {
      if (gql) {
        throw exception;
      }

      const applicationRef =
        this.applicationRef ||
        (this.httpAdapterHost && this.httpAdapterHost.httpAdapter);

      const status = exception.getStatus();
      const response = exception.getResponse();
      const sanitizedResponse = this.sanitizeHttpExceptionResponse(response);

      return applicationRef.reply(
        host.getArgByIndex(1),
        sanitizedResponse,
        status
      );
    }

    this.logger.error((exception as Error)?.message, (exception as Error)?.stack);

    const unprocessableException = new InternalServerErrorException(
      { error: 'Internal Server Error' },
      'An internal error has occurred, and the API was unable to service your request.'
    );

    if (gql) {
      throw unprocessableException;
    }

    const applicationRef =
      this.applicationRef ||
      (this.httpAdapterHost && this.httpAdapterHost.httpAdapter);

    return applicationRef.reply(
      host.getArgByIndex(1),
      unprocessableException.getResponse(),
      unprocessableException.getStatus()
    );
  }

  private sanitizeHttpExceptionResponse(response: string | object) {
    if (typeof response === 'string') {
      return { error: response };
    }

    return this.sanitizeObject(response as Record<string, unknown>);
  }

  private sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
    const sanitizedResponse = {} as Record<string, unknown>;

    for (const [key, value] of Object.entries(obj)) {
      if (
        key === 'line' ||
        key === 'location' ||
        key === 'stack' ||
        key === 'stackTrace'
      ) {
        continue;
      }

      if (Array.isArray(value)) {
        sanitizedResponse[key] = value.map((item) =>
          typeof item === 'object' && item !== null
            ? this.sanitizeObject(item as Record<string, unknown>)
            : item
        );
        continue;
      }

      if (typeof value === 'object' && value !== null) {
        sanitizedResponse[key] = this.sanitizeObject(
          value as Record<string, unknown>
        );
        continue;
      }

      sanitizedResponse[key] = value;
    }

    return sanitizedResponse;
  }
}