import { Logger, UnauthorizedException } from '@nestjs/common';
import { JwtTokenProcessor as JwtTokenProcessor } from './jwt.token.processor';
import { encode, decode } from 'jwt-simple';

export class JwtTokenWithHMACKeysProcessor extends JwtTokenProcessor {
  private static readonly SIGNING_ALGORITHM = 'HS256';

  constructor(private privateKey: string) {
    super(new Logger(JwtTokenWithHMACKeysProcessor.name));
  }

  async validateToken(token: string): Promise<unknown> {
    this.log.debug('Call validateToken');

    const [header] = this.parse(token);
    if (header.alg !== JwtTokenWithHMACKeysProcessor.SIGNING_ALGORITHM) {
      throw new UnauthorizedException('Invalid token signing algorithm');
    }

    return decode(
      token,
      this.privateKey,
      false,
      JwtTokenWithHMACKeysProcessor.SIGNING_ALGORITHM
    );
  }

  async createToken(payload: unknown): Promise<string> {
    this.log.debug('Call createToken');

    const token = encode(
      payload,
      this.privateKey,
      JwtTokenWithHMACKeysProcessor.SIGNING_ALGORITHM
    );
    return token;
  }
}