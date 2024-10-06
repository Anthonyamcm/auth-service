import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import dotenv from 'dotenv';

dotenv.config();

const cognitoClient = new CognitoIdentityProviderClient({
  region: process.env.AWS_REGION,
});

export default cognitoClient;
