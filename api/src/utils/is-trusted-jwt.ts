import jwt from 'jsonwebtoken';
import { getAuthProvider } from '../auth.js';
/**
 * Check if a given string conforms to the structure of a JWT
 * and whether it is issued by a Trusted issuer.
 */
export default async function getTrustedJWTSecret(string: string): Promise<string | null | undefined> {
	try {
		const payload = jwt.decode(string, { json: true });
		if (!payload?.iss) return null;
		const provider = getAuthProvider(payload?.iss);
		return provider.getJWTSecret(string);
	} catch {
		return undefined;
	}
}
