import {
  SignUpCommand,
  AdminInitiateAuthCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
  CognitoIdentityProviderServiceException,
  AuthFlowType,
  AdminInitiateAuthCommandInput,
} from '@aws-sdk/client-cognito-identity-provider';
import cognitoClient from '../utils/awsConfig';
import { CustomError } from '../middlewares/error.middleware';
import Logger from '../utils/logger';
import apiClient from '../utils/apiClient';

export class AuthService {
  private userPoolId = process.env.COGNITO_USER_POOL_ID!;
  private clientId = process.env.COGNITO_CLIENT_ID!;

  async register(identifier: string, password: string, isEmail: boolean) {
    const userAttributes = isEmail
      ? [{ Name: 'email', Value: identifier }]
      : [{ Name: 'phone_number', Value: identifier }];

    const params = {
      ClientId: this.clientId,
      Username: identifier,
      Password: password,
      UserAttributes: userAttributes,
    };

    try {
      const command = new SignUpCommand(params);
      const response = await cognitoClient.send(command);
      Logger.info(`User registration was successful for: ${identifier}`);
      return response;
    } catch (error) {
      const err = error as CognitoIdentityProviderServiceException;
      let message = err.message;
      let status = 400;

      switch (err.name) {
        case 'UsernameExistsException':
          message = 'User already exists';
          status = 409;
          break;
        default:
          message = 'Registration failed';
      }

      Logger.error(`User registration failed for: ${identifier}`, {
        error: err,
      });
      const customError: CustomError = new Error(message);
      customError.status = status;
      throw customError;
    }
  }

  async confirmSignUp(
    identifier: string,
    code: string,
    username: string,
    display_name: string,
    password: string
  ) {
    const params = {
      ClientId: this.clientId,
      Username: identifier,
      ConfirmationCode: code,
      ForceAliasCreation: false,
    };

    try {
      const command = new ConfirmSignUpCommand(params);
      await cognitoClient.send(command);
      Logger.info(`User confirmed successfully for: ${identifier}`);

      const tokens = await this.login(identifier, password);

      if (
        tokens &&
        tokens.AccessToken &&
        tokens.RefreshToken &&
        tokens.IdToken
      ) {
        Logger.info(`User authenticated successfully for: ${identifier}`);

        const decodedIdToken = this.decodeJwt(tokens?.IdToken);
        const cognito_sub = decodedIdToken.sub;

        this.createUserInUserService(
          {
            cognito_sub,
            username,
            display_name,
          },
          tokens.AccessToken
        )
          .then(() => {
            Logger.info(
              `User record created in User-Service for cognito_sub: ${cognito_sub}`
            );
          })
          .catch(error => {
            Logger.error(
              `Failed to create user in User-Service for cognito_sub: ${cognito_sub}`,
              error
            );
            // Optionally, implement retry logic or alerting here
          });

        return tokens;
      } else {
        Logger.error(
          `Authentication failed for: ${identifier}. No tokens returned.`
        );
        throw new Error('Authentication failed. Tokens not received.');
      }
    } catch (error) {
      const err = error as CognitoIdentityProviderServiceException;
      let message = err.message;
      let status = 400;

      switch (err.name) {
        case 'CodeMismatchException':
          message = 'Invalid confirmation code.';
          break;
        case 'ExpiredCodeException':
          message = 'Confirmation code has expired.';
          break;
        case 'NotAuthorizedException':
          message = 'Incorrect username or password.';
          status = 401;
          break;
        case 'UserNotFoundException':
          message = 'User does not exist.';
          break;
        case 'TooManyFailedAttemptsException':
          message = 'Too many failed attempts. Please try again later.';
          status = 429;
          break;
        default:
          message = err.message || 'An error occurred during confirmation.';
      }

      Logger.error(
        `User confirmation/authentication failed for: ${identifier}`,
        {
          error: err,
        }
      );
      const customError: CustomError = new Error(message);
      customError.status = status;
      throw customError;
    }
  }

  /**
   * Logs in a user using AWS Cognito AdminInitiateAuthCommand.
   * @param email - User's email address.
   * @param password - User's password.
   * @returns Authentication result containing tokens.
   * @throws CustomError with appropriate message and status code.
   */
  async login(email: string, password: string) {
    const params: AdminInitiateAuthCommandInput = {
      UserPoolId: this.userPoolId,
      ClientId: this.clientId,
      AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH, // Ensure this flow is enabled for your app client
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
      },
    };

    try {
      const command = new AdminInitiateAuthCommand(params);
      const response = await cognitoClient.send(command);

      if (response.AuthenticationResult) {
        Logger.info(`User login successful for email: ${email}`);
        return response.AuthenticationResult;
      } else {
        Logger.warn(`AuthenticationResult is undefined for email: ${email}`);
      }
    } catch (error) {
      if (error instanceof CognitoIdentityProviderServiceException) {
        let message = error.message;
        let status = 400;

        switch (error.name) {
          case 'NotAuthorizedException':
            message = 'Incorrect username or password';
            status = 401;
            break;
          case 'UserNotConfirmedException':
            message =
              'User not confirmed. Please check your email for confirmation instructions.';
            status = 401;
            break;
          case 'UserNotFoundException':
            message = 'User does not exist';
            status = 404;
            break;
          case 'TooManyRequestsException':
            message = 'Too many requests. Please try again later.';
            status = 429;
            break;
          default:
            message = 'Login failed due to an internal error';
            status = 500;
        }

        Logger.error(`User login failed for email: ${email}`, {
          error: error.message,
          code: error.name,
        });
        const customError: CustomError = new Error(message);
        customError.status = status;
        throw customError;
      } else {
        // Handle unexpected errors
        Logger.error(`Unexpected error during login for email: ${email}`, {
          error,
        });
      }
    }
  }

  async refreshToken(refreshToken: string) {
    const params = {
      AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
      ClientId: this.clientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
      },
    };

    try {
      const command = new InitiateAuthCommand(params);
      const response = await cognitoClient.send(command);
      Logger.info('Token refreshed successfully');
      return response.AuthenticationResult;
    } catch (error) {
      const err = error as CognitoIdentityProviderServiceException;
      let message = err.message;
      let status = 400;

      switch (err.name) {
        case 'NotAuthorizedException':
          message = 'Invalid refresh token';
          status = 401;
          break;
        default:
          message = 'Token refresh failed';
      }

      Logger.error('Token refresh failed', { error: err });
      const customError: CustomError = new Error(message);
      customError.status = status;
      throw customError;
    }
  }

  async initiatePasswordReset(email: string) {
    const params = {
      ClientId: this.clientId,
      Username: email,
    };

    try {
      const command = new ForgotPasswordCommand(params);
      await cognitoClient.send(command);
      Logger.info(`Password reset initiated for email: ${email}`);
    } catch (error) {
      const err = error as CognitoIdentityProviderServiceException;
      let message = err.message;
      let status = 400;

      switch (err.name) {
        case 'UserNotFoundException':
          message = 'User does not exist';
          status = 404;
          break;
        default:
          message = 'Password reset initiation failed';
      }

      Logger.error(`Password reset initiation failed for email: ${email}`, {
        error: err,
      });
      const customError: CustomError = new Error(message);
      customError.status = status;
      throw customError;
    }
  }

  async confirmPasswordReset(email: string, code: string, newPassword: string) {
    const params = {
      ClientId: this.clientId,
      Username: email,
      ConfirmationCode: code,
      Password: newPassword,
    };

    try {
      const command = new ConfirmForgotPasswordCommand(params);
      await cognitoClient.send(command);
      Logger.info(`Password reset confirmed for email: ${email}`);
    } catch (error) {
      const err = error as CognitoIdentityProviderServiceException;
      let message = err.message;
      let status = 400;

      switch (err.name) {
        case 'CodeMismatchException':
          message = 'Invalid confirmation code';
          status = 400;
          break;
        case 'ExpiredCodeException':
          message = 'Confirmation code expired';
          status = 400;
          break;
        default:
          message = 'Password reset confirmation failed';
      }

      Logger.error(`Password reset confirmation failed for email: ${email}`, {
        error: err,
      });
      const customError: CustomError = new Error(message);
      customError.status = status;
      throw customError;
    }
  }

  /**
   * Decodes a JWT token.
   * Note: This method does not verify the token's signature. For verification, use a JWT library.
   * @param token - The JWT token to decode.
   * @returns The decoded token payload.
   */
  private decodeJwt(token: string): any {
    const payload = token.split('.')[1];
    const decoded = Buffer.from(payload, 'base64').toString('utf-8');
    return JSON.parse(decoded);
  }

  /**
   * Communicates with User-Service to create a user record.
   * @param userData - The user data to send.
   */
  private async createUserInUserService(
    userData: {
      cognito_sub: string;
      email?: string;
      phone_number?: string;
      username: string;
      display_name: string;
    },
    idToken: string
  ): Promise<void> {
    try {
      await apiClient.post('/users', userData, {
        headers: {
          Authorization: `Bearer ${idToken}`, // Pass the auth token here
        },
      });
      Logger.info(
        `User record created in User-Service for cognito_sub: ${userData.cognito_sub}`
      );
    } catch (error) {
      Logger.error(
        `Failed to create user in User-Service for cognito_sub: ${userData.cognito_sub}`,
        error
      );
      throw new Error('Failed to create user in User-Service.');
    }
  }
}
