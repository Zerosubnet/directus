import isTrustedJWT from '../../src/utils/is-trusted-jwt.js';
import jwt from 'jsonwebtoken';
import { test, expect } from 'vitest';

test('Returns undefined for non JWT string', () => {
	const result = isTrustedJWT('test');
	expect(result).toBe(undefined);
});

test('Returns undefined for JWTs with text payload', () => {
	const token = jwt.sign('plaintext', 'secret');
	const result = isTrustedJWT(token);
	expect(result).toBe(undefined);
});

test(`Returns undefined if token issuer isn't "external"`, () => {
	const token = jwt.sign({ payload: 'content' }, 'secret', { issuer: 'rijk' });
	const result = isTrustedJWT(token);
	expect(result).toBe(undefined);
});

test(`Returns undefined if token is valid JWT and issuer is "directus"`, () => {
	const token = jwt.sign({ payload: 'content' }, 'secret', { issuer: 'directus' });
	const result = isTrustedJWT(token);
	expect(result).toBe(undefined);
});

test(`Returns secret if token is valid JWT and issuer is "external"`, () => {
	const token = jwt.sign({ payload: 'content' }, 'secret', { issuer: 'external' });
	const result = isTrustedJWT(token);
	expect(result).toBe(String);
});
