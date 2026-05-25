import {
  Controller,
  Get,
  Header,
  HttpException,
  HttpStatus,
  Logger,
  Query
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

@Controller('/api/partners')
@ApiTags('Partners controller')
export class PartnersController {
  private readonly logger = new Logger(PartnersController.name);

  constructor(private readonly partnersService: PartnersService) {}

  private getXPathStringLiteral(value: string): string {
    if (!value.includes("'")) {
      return `'${value}'`;
    }

    if (!value.includes('"')) {
      return `"${value}"`;
    }

    const parts = value.split("'").map((part) => `'${part}'`);
    return `concat(${parts.join(`, "'", `)})`;
  }

  private getScopedPartnerXPath(
    username: string,
    password: string,
    xpath: string
  ): string | null {
    const normalizedXPath = xpath?.trim();

    // Explicitly allow only specific partner fields and scope results to the
    // authenticated partner to prevent unauthorized data access.
    const allowedPathToSuffix = {
      '/partners/partner/name': '/name',
      '/partners/partner/age': '/age',
      '/partners/partner/profession': '/profession',
      '/partners/partner/residency': '/residency',
      '/partners/partner/residency/@country': '/residency/@country',
      '/partners/partner/residency/@state': '/residency/@state',
      '/partners/partner/residency/@city': '/residency/@city',
      '/partners/partner/username': '/username',
      '/partners/partner/wealth': '/wealth'
    };

    const suffix = allowedPathToSuffix[normalizedXPath];

    if (!suffix) {
      return null;
    }

    const escapedUsername = this.getXPathStringLiteral(username);
    const escapedPassword = this.getXPathStringLiteral(password);

    return `//partners/partner[username/text()=${escapedUsername} and password/text()=${escapedPassword}]${suffix}`;
  }

  // **** This is a general XPATH injection EP - Will accept anything ****
  @Get('query')
  @ApiQuery({
    name: 'xpath',
    type: 'string',
    example: '/partners/partner/name',
    required: true
  })
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
    description: API_DESC_QUERY_PARTNERS_RAW
  })
  @ApiOkResponse({
    type: String
  })
  async queryPartnersRaw(
    @Query('xpath') xpath: string,
    @Query('username') username: string,
    @Query('password') password: string
  ): Promise<string> {
    this.logger.debug(`Getting partners with xpath expression "${xpath}"`);

    if (!username || !password) {
      this.logger.warn('Blocked raw partners query due to missing credentials');
      throw new HttpException('Access denied', HttpStatus.FORBIDDEN);
    }

    const scopedXPath = this.getScopedPartnerXPath(username, password, xpath);

    if (!scopedXPath) {
      this.logger.warn(
        `Blocked unauthorized raw partners query for xpath expression "${xpath}"`
      );
      throw new HttpException('Access denied', HttpStatus.FORBIDDEN);
    }

    try {
      const xmlStr = this.partnersService.getPartnersProperties(scopedXPath);

      // Empty result means credentials are invalid for the requested partner scope.
      if (!xmlStr || xmlStr.includes('<root>\n\n</root>')) {
        throw new HttpException('Access denied', HttpStatus.FORBIDDEN);
      }

      return xmlStr;
    } catch (err) {
      if (err instanceof HttpException) {
        throw err;
      }

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
    this.logger.debug(`Trying to login partner with username ${username}`);

    try {
      const xmlStr = this.partnersService.getPartnerLoginProperties(
        username,
        password
      );

      if (!xmlStr) {
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

    try {
      const escapedKeyword = this.getXPathStringLiteral(keyword);
      const xpath = `//partners/partner/name[contains(., ${escapedKeyword})]`;
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