import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { AWS_REGION } from '../config/env';
import Logger from './logger';

let cognitoClient: CognitoIdentityProviderClient | null = null;

/**
 * Initializes and returns the Cognito Identity Provider Client.
 * Utilizes a singleton pattern to ensure only one instance exists.
 * @returns CognitoIdentityProviderClient instance.
 */
export function getCognitoClient(): CognitoIdentityProviderClient {
  if (cognitoClient) {
    return cognitoClient;
  }

  if (!AWS_REGION) {
    Logger.error('AWS_REGION is not set in environment variables.');
    throw new Error('AWS_REGION is not set in environment variables.');
  }

  cognitoClient = new CognitoIdentityProviderClient({ region: AWS_REGION });
  Logger.info('CognitoIdentityProviderClient initialized.');
  return cognitoClient;
}

// Initialize the client immediately
const client = getCognitoClient();

export default client;
