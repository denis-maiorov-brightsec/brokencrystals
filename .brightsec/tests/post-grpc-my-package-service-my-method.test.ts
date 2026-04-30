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

test('POST /grpc/my.package.Service/MyMethod', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'ssrf',
        'proto_pollution',
        'file_upload',
        'csrf',
        'version_control_systems',
        'full_path_disclosure',
        'html_injection',
        'improper_asset_management',
        'secret_tokens'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: [
          'PostgreSQL (via @mikro-orm/postgresql and pg)'
        ],
        user_roles: ['admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/grpc/my.package.Service/MyMethod`,
      headers: {
        Accept: 'application/grpc-web+proto',
        'Content-Type': 'application/grpc-web+proto',
        Host: 'grpc-backend.example.com',
        TE: 'trailers',
        'User-Agent': 'grpc-web/1.0',
        'X-Grpc-Web': '1'
      },
      body: { message: 'Hello, service!' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});