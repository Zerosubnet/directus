import jwt from 'jsonwebtoken';
import { InvalidTokenError, ServiceUnavailableError, TokenExpiredError } from '../errors/index.js';
import type { DirectusTokenPayload } from '../types/index.js';

export function verifyJWT(token: string, secret: string, issuer?: 'directus'): Record<string, any> {
	let payload;

	try {
		payload = jwt.verify(token, secret, {
			issuer,
		}) as Record<string, any>;
	} catch (err) {
		if (err instanceof jwt.TokenExpiredError) {
			throw new TokenExpiredError();
		} else if (err instanceof jwt.JsonWebTokenError) {
			throw new InvalidTokenError();
		} else {
			throw new ServiceUnavailableError({ service: 'jwt', reason: `Couldn't verify token.` });
		}
	}

	return payload;
}

export function verifyAccessJWT(token: string, secret: string, issuer?: 'directus'): DirectusTokenPayload {
	const { id, role, app_access, admin_access, share, share_scope } = verifyJWT(token, secret, issuer);

	if (role === undefined || app_access === undefined || admin_access === undefined) {
		throw new InvalidTokenError();
	}

	return { id, role, app_access, admin_access, share, share_scope };
}
