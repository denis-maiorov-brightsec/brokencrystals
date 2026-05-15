import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  Header,
  HttpException,
  HttpStatus,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  Options,
  Param,
  Post,
  Put,
  Query,
  Req,
  Res,
  SerializeOptions,
  UnauthorizedException,
  UseGuards,
  UseInterceptors
} from '@nestjs/common';
import {
  ApiConflictResponse,
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags,
  ApiUnauthorizedResponse,
  ApiExcludeEndpoint
} from '@nestjs/swagger';
import { CreateUserRequest, SignupMode } from './api/CreateUserRequest';
import { UserDto } from './api/UserDto';
import { LdapQueryHandler } from './ldap.query.handler';
import { UsersService } from './users.service';
import { User } from '../model/user.entity';
import { AuthGuard } from '../auth/auth.guard';
import { JwtType } from '../auth/jwt/jwt.type.decorator';
import { JwtProcessorType } from '../auth/auth.service';
import { FastifyReply, FastifyRequest } from 'fastify';
import { AnyFilesInterceptor } from '../components/any-files.interceptor';
import { KeyCloakService } from '../keycloak/keycloak.service';
import {
  SWAGGER_DESC_CREATE_BASIC_USER,
  SWAGGER_DESC_PHOTO_USER_BY_EMAIL,
  SWAGGER_DESC_FIND_USER,
  SWAGGER_DESC_LDAP_SEARCH,
  SWAGGER_DESC_OPTIONS_REQUEST,
  SWAGGER_DESC_UPLOAD_USER_PHOTO,
  SWAGGER_DESC_CREATE_OIDC_USER,
  SWAGGER_DESC_UPDATE_USER_INFO,
  SWAGGER_DESC_ADMIN_RIGHTS,
  SWAGGER_DESC_FIND_USERS,
  SWAGGER_DESC_FIND_FULL_USER_INFO,
  SWAGGER_DESC_DELETE_PHOTO_USER_BY_ID,
  SWAGGER_DESC_GET_SELF,
  SWAGGER_DESC_UPDATE_SELF
} from './users.controller.swagger.desc';
import { AdminGuard } from './users.guard';
import { PermissionDto } from './api/PermissionDto';
import { BASIC_USER_INFO, FULL_USER_INFO } from './api/UserDto';
import { parseXml } from 'libxmljs';

@Controller('/api/users')
@UseInterceptors(ClassSerializerInterceptor)
@ApiTags('User controller')
export class UsersController {
  private logger = new Logger(UsersController.name);
  private ldapQueryHandler = new LdapQueryHandler();

  constructor(
    private readonly usersService: UsersService,
    private readonly keyCloakService: KeyCloakService
  ) {}

  @Get('/id/:id')
  @ApiQuery({ name: 'id', example: 1, required: true })
  @SerializeOptions({ groups: [BASIC_USER_INFO] })
  @ApiOperation({
    description: SWAGGER_DESC_FIND_USER
  })
  @ApiOkResponse({
    type: UserDto,
    description: 'Returns basic user info if it exists'
  })
  @ApiNotFoundResponse({
    description: 'User not found',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number' },
        message: { type: 'string' }
      }
    }
  })
  async getById(@Param('id') id: number, @Req() req: FastifyRequest): Promise<UserDto> {
    try {
      this.logger.debug(`Find a user by id: ${id}`);
      const user = await this.usersService.findById(id);
      const requestingUserEmail = this.originEmail(req);

      if (user.email !== requestingUserEmail) {
        throw new ForbiddenException('Access denied to this user information.');
      }

      return new UserDto(user);
    } catch (err) {
      throw new HttpException(err.message, err.status);
    }
  }

  public originEmail(request: FastifyRequest): string {
    return JSON.parse(
      Buffer.from(
        request.headers.authorization.split('.')[1],
        'base64'
      ).toString()
    ).user;
  }
}