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

test('PUT /grpc/my.package.Service/UnaryCall', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'http_method_fuzzing',
        'ssrf',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'csrf',
        'improper_asset_management',
        'version_control_systems',
        'full_path_disclosure',
        'html_injection',
        'xss',
        'proto_pollution'
      ],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY],
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
      method: HttpMethod.PUT,
      url: `${baseUrl}/grpc/my.package.Service/UnaryCall`,
      headers: {
        Accept: 'application/grpc-web',
        Connection: 'keep-alive',
        'Content-Length': '42',
        'Content-Type': 'application/grpc-web',
        Host: 'example.com',
        TE: 'trailers',
        'User-Agent': 'grpc-web-javascript/1.0',
        'X-Grpc-Web': '1'
      },
      body: 'BASE64_BINARY_PAYLOAD== (example: serialized protobuf request, base64-encoded) ',
      auth: process.env.BRIGHT_AUTH_ID
    });
});