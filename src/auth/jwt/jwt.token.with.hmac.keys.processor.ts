import { Logger } from '@nestjs/common';
import { JwtTokenProcessor as JwtTokenProcessor } from './jwt.token.processor';
import { encode, decode } from 'jwt-simple';

export class JwtTokenWithHMACKeysProcessor extends JwtTokenProcessor {
  private static readonly JWT_ALGORITHM = 'HS256';

  constructor(private privateKey: string) {
    super(new Logger(JwtTokenWithHMACKeysProcessor.name));
  }

  async validateToken(token: string): Promise<unknown> {
    this.log.debug('Call validateToken');

    const [header] = this.parse(token);
    if (header.alg !== JwtTokenWithHMACKeysProcessor.JWT_ALGORITHM) {
      throw new Error('Invalid token algorithm');
    }

    return decode(
      token,
      this.privateKey,
      false,
      JwtTokenWithHMACKeysProcessor.JWT_ALGORITHM
    );
  }

  async createToken(payload: unknown): Promise<string> {
    this.log.debug('Call createToken');

    const token = encode(
      payload,
      this.privateKey,
      JwtTokenWithHMACKeysProcessor.JWT_ALGORITHM
    );
    return token;
  }
}