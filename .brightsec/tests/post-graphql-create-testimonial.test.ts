import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSize = (() => {
  const value = Number(process.env.SECTESTER_SCAN_POOL_SIZE);
  return value ? value : undefined;
})();

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /graphql createTestimonial', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'jwt',
        'csrf',
        'graphql_introspection',
        'sqli',
        'open_database',
        'full_path_disclosure',
        'secret_tokens',
        'ssrf',
        'server_side_js_injection'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/brokencrystals:stable',
        databases: ['PostgreSQL', 'MikroORM'],
        user_roles: ['admin', 'user']
      },
      poolSize
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/graphql`,
      body: {
        operationName: 'createTestimonial',
        query: 'mutation createTestimonial($testimonialRequest: CreateTestimonialRequest!) { createTestimonial(testimonialRequest: $testimonialRequest) { name title message } }',
        variables: {
          testimonialRequest: {
            name: 'Alice Johnson',
            title: 'Product Manager',
            message: 'Broken Crystals helped us validate our security testing workflow quickly.'
          }
        }
      },
      headers: { 'Content-Type': 'application/json', authorization: 'Bearer <valid-rsa-jwt>' }
    });
});