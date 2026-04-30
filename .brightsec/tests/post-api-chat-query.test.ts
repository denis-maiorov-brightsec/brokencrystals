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

test('POST /api/chat/query', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'prompt_injection',
        'csrf',
        'xss',
        'html_injection',
        'css_injection',
        'iframe_injection',
        'proto_pollution',
        'full_path_disclosure'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/api/chat/query`,
      body: [
        {
          role: 'user',
          content: "Hello! Can you summarize the key concepts of dependency injection in a few sentences?"
        },
        {
          role: 'assistant',
          content: "Dependency injection is a design pattern where an object's dependencies are provided externally rather than created inside the object. It improves modularity and testability by decoupling components and allowing easy substitution of implementations. In frameworks like NestJS, DI is typically handled by a container that instantiates and injects providers based on metadata or configuration."
        },
        {
          role: 'user',
          content: 'Please provide a short example in TypeScript.'
        }
      ],
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json'
      },
      auth: process.env.BRIGHT_AUTH_ID
    });
});