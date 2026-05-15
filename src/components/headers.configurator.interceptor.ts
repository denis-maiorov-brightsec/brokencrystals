import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { FastifyReply, FastifyRequest } from 'fastify';

@Injectable()
export class HeadersConfiguratorInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest<FastifyRequest>();
    const res = context.switchToHttp().getResponse<FastifyReply>();

    return next.handle().pipe(
      tap(() => {
        // Ensure the cookie is set securely
        res.setCookie('bc-calls-counter', Date.now().toString(), {
          secure: true, // Only send the cookie over HTTPS
          httpOnly: true, // Prevent client-side access to the cookie
          sameSite: 'Strict', // Restrict cross-site cookie sending
          domain: req.hostname, // Restrict the cookie to the specific domain
          path: '/', // Ensure the cookie is valid for the entire domain
        });

        // Set security headers
        res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        res.header('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none';");
        res.header('X-Content-Type-Options', 'nosniff');
        res.header('X-XSS-Protection', '1; mode=block');
      })
    );
  }
}