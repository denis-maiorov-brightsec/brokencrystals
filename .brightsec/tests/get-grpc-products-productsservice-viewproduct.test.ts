import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /grpc/products.ProductsService/ViewProduct?timeout=10s', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'ssrf',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'id_enumeration',
        'proto_pollution',
        'html_injection',
        'full_path_disclosure',
        'improper_asset_management',
        'csrf',
        'server_side_js_injection',
        'version_control_systems'
      ],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL (via @mikro-orm/postgresql and pg)'],
        user_roles: ['admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.VIEW,
      url: `${baseUrl}/grpc/products.ProductsService/ViewProduct?timeout=10s`,
      headers: {
        Accept: 'application/grpc-web+proto, application/grpc-web, application/grpc',
        Host: 'example.com',
        TE: 'trailers',
        'User-Agent': 'grpc-web-client/1.0',
        'x-grpc-web': '1'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});