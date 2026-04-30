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

test('PUT /api/file/raw?path=some%2Fpath%2Fto%2Ffile.png', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'file_upload',
        'lfi',
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'csrf',
        'http_method_fuzzing',
        'secret_tokens',
        'ssti',
        'full_path_disclosure',
        {
          name: 'date_manipulation',
          options: {
            skipStaticParams: false
          }
        }
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.QUERY],
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
      url: `${baseUrl}/api/file/raw?path=some%2Fpath%2Fto%2Ffile.png`,
      body: `Hello, this is the raw file content for upload.
You can put binary data as a string or any textual content here.`,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'text/plain; charset=utf-8'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});