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

test('PUT /api/users/one/john.doe@example.com/info', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        {
          name: 'broken_access_control',
          options: {
            auth: process.env.BRIGHT_AUTH_ID
          }
        },
        'jwt',
        'bopla',
        'proto_pollution',
        'csrf',
        'id_enumeration',
        'xss',
        'html_injection',
        'date_manipulation'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.PATH],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL', 'MikroORM'],
        user_roles: ['admin', 'user']
      },
      poolSize: Number(process.env.SECTESTER_SCAN_POOL_SIZE) || undefined,
      skipStaticParams: false
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/users/one/john.doe@example.com/info`,
      body: {
        email: 'john.doe@example.com',
        firstName: 'John',
        lastName: 'Doe',
        company: 'Bright Security',
        id: 1,
        cardNumber: '4263982640269299',
        phoneNumber: '12065550100',
        password: 'Pa55w0rd',
        updatedAt: '2024-01-01T00:00:00.000Z',
        createdAt: '2024-01-01T00:00:00.000Z'
      },
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer eyJ1c2VyIjoiam9obi5kb2VAZXhhbXBsZS5jb20ifQ.signature' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});