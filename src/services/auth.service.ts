import {
  SignUpCommand,
  AdminInitiateAuthCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  ForgotPasswordCommand,
  ConfirmForgotPasswordCommand,
  CognitoIdentityProviderServiceException,
  AuthFlowType,
} from '@aws-sdk/client-cognito-identity-provider';
import { Logger } from '../utils/logger';
import cognitoClient from '../utils/awsConfig';
import { CustomError } from '../middlewares/error.middleware';

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

  async login(email: string, password: string) {
    const params = {
      UserPoolId: this.userPoolId,
      ClientId: this.clientId,
      AuthFlow: AuthFlowType.ADMIN_NO_SRP_AUTH,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
      },
    };

    try {
      const command = new AdminInitiateAuthCommand(params);
      const response = await cognitoClient.send(command);
      Logger.info(`User login successful for email: ${email}`);
      return response.AuthenticationResult;
    } catch (error) {
      const err = error as CognitoIdentityProviderServiceException;
      let message = err.message;
      let status = 400;

      switch (err.name) {
        case 'NotAuthorizedException':
          message = 'Incorrect username or password';
          status = 401;
          break;
        case 'UserNotConfirmedException':
          message = 'User not confirmed';
          status = 401;
          break;
        default:
          message = 'Login failed';
      }

      Logger.error(`User login failed for email: ${email}`, { error: err });
      const customError: CustomError = new Error(message);
      customError.status = status;
      throw customError;
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
