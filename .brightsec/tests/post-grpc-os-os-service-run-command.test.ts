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

test('POST /grpc/os.OsService/RunCommand', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'osi',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'ssrf',
        'csrf'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL'],
        user_roles: ['admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/grpc/os.OsService/RunCommand`,
      body: 'AAAAAAgKBndob2FtaQ==',
      headers: {
        accept: 'application/grpc-web-text+proto',
        'content-type': 'application/grpc-web-text+proto',
        te: 'trailers',
        'x-grpc-web': '1'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});