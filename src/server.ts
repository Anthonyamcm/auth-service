import app from './app';
import Logger from './utils/logger';
import AuthService from './services/auth.service';
import {
  COGNITO_USER_POOL_ID,
  COGNITO_CLIENT_ID,
  COGNITO_REGION,
} from './config/env';

const PORT = process.env.PORT || 3000;

let authService: AuthService;

try {
  // Initialize AuthService with environment variables
  const cognitoConfig = {
    userPoolId: COGNITO_USER_POOL_ID,
    clientId: COGNITO_CLIENT_ID,
    userPoolRegion: COGNITO_REGION,
  };

  authService = new AuthService(cognitoConfig);

  // Attach authService to app.locals for access in controllers
  app.locals.authService = authService;

  // Start the server
  app.listen(PORT, () => {
    Logger.info(`Server is running on port ${PORT}`);
  });
} catch (error) {
  Logger.error('Failed to initialize AuthService:', { error });
  process.exit(1);
}
