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

  private isAllowedRawXPath(xpath: string): boolean {
    const normalizedXPath = xpath?.trim();

    // Allow only read-only access to public partner fields for anonymous callers.
    // This prevents unauthorized access to restricted partner resources.
    const allowedPublicXPathPatterns = [
      /^\/partners\/partner\/(name|age|profession)$/,
      /^\/partners\/partner\/residency$/,
      /^\/partners\/partner\/residency\/@(country|state|city)$/
    ];

    return allowedPublicXPathPatterns.some((pattern) =>
      pattern.test(normalizedXPath)
    );
  }

  // **** This is a general XPATH injection EP - Will accept anything ****
  @Get('query')
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

    if (!this.isAllowedRawXPath(xpath)) {
      this.logger.warn(
        `Blocked unauthorized raw partners query for xpath expression "${xpath}"`
      );
      throw new HttpException('Access denied', HttpStatus.FORBIDDEN);
    }

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
    this.logger.debug(`Trying to login partner with username ${username}`);

    try {
      const escapedUsername = this.getXPathStringLiteral(username);
      const escapedPassword = this.getXPathStringLiteral(password);
      const xpath = `//partners/partner[username/text()=${escapedUsername} and password/text()=${escapedPassword}]/*`;
      const xmlStr = this.partnersService.getPartnersProperties(xpath);

      // Check if account's data contains any information - If not, the login failed!
      if (
        !(xmlStr && xmlStr.includes('password') && xmlStr.includes('wealth'))
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