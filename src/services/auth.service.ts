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

export class AuthService {
  private userPoolId = process.env.COGNITO_USER_POOL_ID!;
  private clientId = process.env.COGNITO_CLIENT_ID!;

  async register(email: string, password: string) {
    const params = {
      ClientId: this.clientId,
      Username: email,
      Password: password,
      UserAttributes: [
        {
          Name: 'email',
          Value: email,
        },
      ],
    };

    try {
      const command = new SignUpCommand(params);
      const response = await cognitoClient.send(command);
      Logger.info(`User registration successful for email: ${email}`);
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

      Logger.error(`User registration failed for email: ${email}`, {
        error: err,
      });
      const customError: CustomError = new Error(message);
      customError.status = status;
      throw customError;
    }
  }

  async confirmSignUp(email: string, code: string) {
    const params = {
      ClientId: this.clientId,
      Username: email,
      ConfirmationCode: code,
    };

    try {
      const command = new ConfirmSignUpCommand(params);
      await cognitoClient.send(command);
      Logger.info(`User confirmed successfully for email: ${email}`);
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
          message = 'Confirmation failed';
      }

      Logger.error(`User confirmation failed for email: ${email}`, {
        error: err,
      });
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
}
