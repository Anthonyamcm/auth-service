import dotenv from 'dotenv';
import Logger from '../utils/logger';

dotenv.config();

export const ENVIRONMENT = process.env.NODE_ENV || 'development';

// Validate required environment variables
const requiredEnvVars = [
  'AWS_REGION',
  'COGNITO_USER_POOL_ID',
  'COGNITO_CLIENT_ID',
  'COGNITO_REGION',
  'USER_SERVICE_URL',
  'PORT',
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  Logger.error('Missing required environment variables:', { missingEnvVars });
  throw new Error(
    `Missing required environment variables: ${missingEnvVars.join(', ')}`
  );
}

// Export other environment variables as needed
export const PORT = process.env.PORT;
export const AWS_REGION = process.env.AWS_REGION;
export const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID!;
export const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID!;
export const COGNITO_REGION = process.env.COGNITO_REGION!;
export const USER_SERVICE_URL = process.env.USER_SERVICE_URL!;
