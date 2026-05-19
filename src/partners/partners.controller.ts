import {
  Controller,
  Get,
  Header,
  HttpException,
  HttpStatus,
  Logger,
  Query,
  UseGuards
} from '@nestjs/common';
import {
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags
} from '@nestjs/swagger';
import {
  API_DESC_QUERY_PARTNERS_RAW,
  API_DESC_PARTNERS_LOGIN,
  API_DESC_SEARCH_PARTNERS_NAMES
} from './partners.controller.swagger.desc';
import { PartnersService } from './partners.service';
import { AuthGuard } from '../auth/auth.guard';
import { JwtProcessorType } from '../auth/auth.service';
import { JwtType } from '../auth/jwt/jwt.type.decorator';

@Controller('/api/partners')
@ApiTags('Partners controller')
export class PartnersController {
  private readonly logger = new Logger(PartnersController.name);
  private readonly PARTNER_CREDENTIAL_REGEX = /^[A-Za-z0-9_!.-]{1,64}$/;

  constructor(private readonly partnersService: PartnersService) {}

  private isValidPartnerCredentialInput(value: string): boolean {
    return !!value && this.PARTNER_CREDENTIAL_REGEX.test(value);
  }

  private toXPathStringLiteral(value: string): string {
    if (!value.includes("'")) {
      return `'${value}'`;
    }

    if (!value.includes('"')) {
      return `"${value}"`;
    }

    return `concat('${value.split("'").join(`', "'", '`)}')`;
  }

  // **** This is a general XPATH injection EP - Will accept anything ****
  @Get('query')
  @UseGuards(AuthGuard)
  @JwtType(JwtProcessorType.RSA)
  @ApiQuery({
    name: 'xpath',
    type: 'string',
    example: '/partners/partner/name',
    required: true
  })
  @Header('content-type', 'text/xml')
  @ApiOperation({
    description: API_DESC_QUERY_PARTNERS_RAW
  })
  @ApiOkResponse({
    type: String
  })
  async queryPartnersRaw(@Query('xpath') xpath: string): Promise<string> {
    this.logger.debug(`Getting partners with xpath expression "${xpath}"`);

    try {
      return this.partnersService.getPartnersProperties(xpath);
    } catch (err) {
      throw new HttpException(
        `Failed to load XML using XPATH. Details: ${err}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  // **** This is a boolean based XPATH injection EP ****
  @Get('partnerLogin')
  @ApiQuery({
    name: 'username',
    type: 'string',
    example: 'walter100',
    required: true
  })
  @ApiQuery({
    name: 'password',
    type: 'string',
    example: 'Heisenberg123',
    required: true
  })
  @Header('content-type', 'text/xml')
  @ApiOperation({
    description: API_DESC_PARTNERS_LOGIN
  })
  @ApiOkResponse({
    type: String
  })
  async partnerLogin(
    @Query('username') username: string,
    @Query('password') password: string
  ): Promise<string> {
    this.logger.debug(
      `Trying to login partner with username ${username} using password ${password}`
    );

    if (
      !this.isValidPartnerCredentialInput(username) ||
      !this.isValidPartnerCredentialInput(password)
    ) {
      throw new HttpException(
        `Access denied to partner's account. Invalid credentials format`,
        HttpStatus.FORBIDDEN
      );
    }

    try {
      const xpath = `//partners/partner[username/text()='${username}' and password/text()='${password}']/*`;
      const xmlStr = this.partnersService.getPartnersProperties(xpath);

      // Check if account's data contains any information - If not, the login failed!
      if (
        !(
          xmlStr &&
          xmlStr.includes(`<username>${username}</username>`) &&
          xmlStr.includes(`<password>${password}</password>`) &&
          xmlStr.includes('wealth')
        )
      ) {
        throw new Error('Login attempt failed!');
      }

      return xmlStr;
    } catch (err) {
      const errStr = err.toString();
      const errorMessage = errStr.includes('Unterminated string literal')
        ? 'Error in XPath expression'
        : errStr;

      throw new HttpException(
        `Access denied to partner's account. ${errorMessage}`,
        HttpStatus.FORBIDDEN
      );
    }
  }

  // **** This is a string based XPATH injection EP ****
  @Get('searchPartners')
  @ApiQuery({
    name: 'keyword',
    type: 'string',
    example: 'Walter',
    required: true
  })
  @Header('content-type', 'text/xml')
  @ApiOperation({
    description: API_DESC_SEARCH_PARTNERS_NAMES
  })
  @ApiOkResponse({
    type: String
  })
  async searchPartners(@Query('keyword') keyword: string): Promise<string> {
    this.logger.debug(`Searching partner names by the keyword "${keyword}"`);

    const normalizedKeyword = (keyword || '').trim();
    if (!normalizedKeyword || normalizedKeyword.length > 64) {
      throw new HttpException(
        `Couldn't find partners. Invalid search keyword format`,
        HttpStatus.BAD_REQUEST
      );
    }

    try {
      const xpathKeyword = this.toXPathStringLiteral(normalizedKeyword);
      const xpath = `//partners/partner/name[contains(., ${xpathKeyword})]`;
      return this.partnersService.getPartnersProperties(xpath);
    } catch (err) {
      const errStr = err.toString();
      const errorMessage =
        errStr.includes('XPath parse error') ||
        errStr.includes('Unterminated string literal')
          ? 'Error in XPath expression'
          : errStr;

      throw new HttpException(
        `Couldn't find partners. ${errorMessage}`,
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }
}