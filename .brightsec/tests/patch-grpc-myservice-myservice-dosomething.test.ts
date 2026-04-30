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

test('PATCH /grpc/myservice.MyService/DoSomething', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'proto_pollution',
        'csrf',
        'version_control_systems',
        'improper_asset_management',
        'full_path_disclosure',
        'http_method_fuzzing',
        'jwt'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: [
          'PostgreSQL (via @mikro-orm/postgresql and pg)'
        ],
        user_roles: [
          'admin'
        ]
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PATCH,
      url: `${baseUrl}/grpc/myservice.MyService/DoSomething`,
      headers: {
        Accept: 'application/grpc-web+json',
        Authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.token',
        'Content-Type': 'application/grpc-web+json',
        Host: 'example.com',
        Origin: 'https://example.com',
        TE: 'trailers',
        'User-Agent': 'brokencrystals-client/1.0',
        'X-Grpc-Web': '1'
      },
      body: {
        id: '123',
        name: 'Test item',
        active: true
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});