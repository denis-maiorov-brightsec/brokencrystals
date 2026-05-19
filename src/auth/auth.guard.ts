import {
  CanActivate,
  Injectable,
  Logger,
  UnauthorizedException,
  ExecutionContext
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthService, JwtProcessorType } from './auth.service';
import { JwTypeMetadataField } from './jwt/jwt.type.decorator';
import { FastifyRequest } from 'fastify';
import { GqlContextType, GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class AuthGuard implements CanActivate {
  private static readonly AUTH_HEADER = 'authorization';
  private static readonly BEARER_PREFIX = 'bearer';
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private readonly authService: AuthService,
    private readonly reflector: Reflector
  ) {}

  async canActivate(context: ExecutionContext) {
    try {
      this.logger.debug('Called canActivate');
      const request = this.getRequest(context);
      const token = this.extractToken(request);

      if (!token) {
        return false;
      }

      return await this.verifyToken(token, context);
    } catch (err) {
      this.logger.debug(`Failed to validate token: ${err.message}`);
      throw new UnauthorizedException({
        error: 'Unauthorized'
      });
    }
  }

  private extractToken(request: FastifyRequest): string | undefined {
    let token = request.headers[AuthGuard.AUTH_HEADER];

    if (!token?.length) {
      token = request.cookies[AuthGuard.AUTH_HEADER];
    }

    if (this.checkIsBearer(token)) {
      token = token.substring(AuthGuard.BEARER_PREFIX.length).trim();
    }

    return token?.length ? token : undefined;
  }

  private getRequest(context: ExecutionContext): FastifyRequest {
    return context.getType<GqlContextType>() === 'graphql'
      ? GqlExecutionContext.create(context).getContext().req
      : context.switchToHttp().getRequest();
  }

  private async verifyToken(
    token: string,
    context: ExecutionContext
  ): Promise<boolean> {
    this.validateTokenAlgorithm(token);

    const processorType = this.reflector.get<JwtProcessorType>(
      JwTypeMetadataField,
      context.getHandler()
    );

    const effectiveProcessorType =
      processorType === undefined ? JwtProcessorType.BEARER : processorType;

    return !!(await this.authService.validateToken(token, effectiveProcessorType));
  }

  private validateTokenAlgorithm(token: string): void {
    const tokenParts = token.split('.');

    if (tokenParts.length !== 3 || !tokenParts[0]) {
      throw new Error('Invalid JWT token format');
    }

    const normalizedHeader = tokenParts[0].replace(/-/g, '+').replace(/_/g, '/');
    const header = JSON.parse(
      Buffer.from(normalizedHeader, 'base64').toString('utf8')
    );

    if (!header?.alg || header.alg.toLowerCase() === 'none') {
      throw new Error('Invalid JWT signing algorithm');
    }
  }

  private checkIsBearer(bearer: string): boolean {
    return (
      !!bearer &&
      bearer.toLowerCase().startsWith(AuthGuard.BEARER_PREFIX.toLowerCase())
    );
  }
}