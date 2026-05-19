import { Logger, UnauthorizedException } from '@nestjs/common';
import { decode, encode } from 'jwt-simple';
import { JwtTokenProcessor as JwtTokenProcessor } from './jwt.token.processor';

export class JwtTokenWithRSAKeysProcessor extends JwtTokenProcessor {
  private static readonly SIGNING_ALGORITHM = 'RS256';

  constructor(
    private publicKey: string,
    private privateKey: string
  ) {
    super(new Logger(JwtTokenWithRSAKeysProcessor.name));
  }

  async validateToken(token: string): Promise<unknown> {
    this.log.debug('Call validateToken');

    const [header] = this.parse(token);
    if (header.alg !== JwtTokenWithRSAKeysProcessor.SIGNING_ALGORITHM) {
      throw new UnauthorizedException('Invalid token signing algorithm');
    }

    return decode(
      token,
      this.publicKey,
      false,
      JwtTokenWithRSAKeysProcessor.SIGNING_ALGORITHM
    );
  }

  async createToken(payload: unknown): Promise<string> {
    this.log.debug('Call createToken');

    const token = encode(
      payload,
      this.privateKey,
      JwtTokenWithRSAKeysProcessor.SIGNING_ALGORITHM
    );
    return token;
  }
}