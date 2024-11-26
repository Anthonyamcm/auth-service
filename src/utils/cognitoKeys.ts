import axios from 'axios';
import jwkToPem from 'jwk-to-pem';
import Logger from './logger';

export interface CognitoKey {
  kid: string;
  alg: string;
  kty: string;
  e: string;
  n: string;
  use: string;
  pem: string;
}

// Optional: Cache the keys to avoid fetching them every time
let cachedKeys: { [key: string]: CognitoKey } | null = null;

/**
 * Fetches and converts Cognito JWKs to PEM format.
 * Caches the keys to minimize network requests.
 * @param userPoolId - The Cognito User Pool ID.
 * @param region - The AWS region of the User Pool.
 * @returns A mapping from `kid` to `CognitoKey` containing PEM.
 */
export async function getCognitoPublicKeys(
  userPoolId: string,
  region: string
): Promise<{ [key: string]: CognitoKey }> {
  if (cachedKeys) {
    Logger.info('Using cached Cognito public keys.');
    return cachedKeys;
  }

  const url = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`;

  try {
    const response = await axios.get(url);
    const { keys } = response.data;

    if (!keys || !Array.isArray(keys)) {
      Logger.error('Invalid JWKS format received from Cognito.', {
        jwks: response.data,
      });
      throw new Error('Invalid JWKS format.');
    }

    const cognitoKeys: { [key: string]: CognitoKey } = {};

    keys.forEach((key: any) => {
      try {
        const pem = jwkToPem(key);
        cognitoKeys[key.kid] = { ...key, pem };
      } catch (conversionError) {
        Logger.error('Failed to convert JWK to PEM.', {
          key,
          error: conversionError,
        });
        // Optionally, you can choose to skip this key or rethrow the error
      }
    });

    if (Object.keys(cognitoKeys).length === 0) {
      Logger.error('No valid Cognito public keys were processed.', { keys });
      throw new Error('No valid Cognito public keys found.');
    }

    cachedKeys = cognitoKeys; // Cache the keys
    Logger.info(
      `Successfully fetched and cached ${Object.keys(cognitoKeys).length} Cognito keys.`
    );
    return cognitoKeys;
  } catch (error) {
    Logger.error('Failed to retrieve Cognito public keys.', { error });
    throw new Error('Failed to retrieve Cognito public keys.');
  }
}
