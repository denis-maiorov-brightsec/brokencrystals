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

test('DELETE /grpc/helloworld.Greeter/SayHello?force=true&reason=cleanup', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'csrf',
        'http_method_fuzzing',
        'ssrf',
        'version_control_systems',
        'full_path_disclosure',
        'html_injection',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'proto_pollution'
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.QUERY,
        AttackParamLocation.HEADER,
        AttackParamLocation.PATH
      ],
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
      method: HttpMethod.DELETE,
      url: `${baseUrl}/grpc/helloworld.Greeter/SayHello?force=true&reason=cleanup`,
      body: {
        id: '123e4567-e89b-12d3-a456-426614174000',
        message: 'delete request'
      },
      headers: {
        Accept: '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        Connection: 'keep-alive',
        'Content-Type': 'application/json',
        Host: 'example.com',
        Origin: 'https://example.com',
        'User-Agent': 'Mozilla/5.0 (compatible; BrokenCrystals/1.0)'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});