import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Destructure required environment variables
const { AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY } = process.env;

// Validate essential environment variables
if (!AWS_REGION) {
  throw new Error('Missing AWS_REGION environment variable');
}

if (!AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
  throw new Error('Missing AWS credentials in environment variables');
}

// Initialize the Cognito Identity Provider Client
const cognitoClient = new CognitoIdentityProviderClient({
  region: AWS_REGION,
  credentials: {
    accessKeyId: AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
  },
});

export default cognitoClient;
