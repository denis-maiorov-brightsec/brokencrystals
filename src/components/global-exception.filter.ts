import {
  ArgumentsHost,
  Catch,
  HttpException,
  InternalServerErrorException
} from '@nestjs/common';
import { BaseExceptionFilter } from '@nestjs/core';
import { GqlContextType } from '@nestjs/graphql';

@Catch()
export class GlobalExceptionFilter extends BaseExceptionFilter {
  public catch(exception: unknown, host: ArgumentsHost) {
    const gql = host.getType<GqlContextType>() === 'graphql';

    if (exception instanceof HttpException) {
      const sanitizedException = new HttpException(
        this.sanitizeHttpResponse(exception.getResponse()),
        exception.getStatus()
      );

      if (gql) {
        throw sanitizedException;
      }

      const applicationRef =
        this.applicationRef ||
        (this.httpAdapterHost && this.httpAdapterHost.httpAdapter);

      return applicationRef.reply(
        host.getArgByIndex(1),
        sanitizedException.getResponse(),
        sanitizedException.getStatus()
      );
    }

    const unprocessableException = new InternalServerErrorException(
      { error: (exception as Error).message },
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

  private sanitizeHttpResponse(response: string | object): object {
    if (typeof response === 'string') {
      return { error: response };
    }

    const sanitizedResponse = { ...(response as Record<string, unknown>) };

    delete sanitizedResponse.line;
    delete sanitizedResponse.path;
    delete sanitizedResponse.location;
    delete sanitizedResponse.stack;
    delete sanitizedResponse.trace;

    return sanitizedResponse;
  }
}