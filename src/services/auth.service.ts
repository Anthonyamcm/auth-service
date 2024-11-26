// src/services/auth.service.ts

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
  SignUpCommandInput,
  ConfirmSignUpCommandInput,
  InitiateAuthCommandInput,
  ForgotPasswordCommandInput,
  ConfirmForgotPasswordCommandInput,
} from '@aws-sdk/client-cognito-identity-provider';
import cognitoClient from '../utils/awsConfig';
import { CustomError } from '../middlewares/error.middleware';
import Logger from '../utils/logger';
import apiClient from '../utils/apiClient';
import { AxiosResponse } from 'axios';
import jwt from 'jsonwebtoken';
import retry from 'async-retry';
import {
  validateIdentifier,
  validatePassword,
  validateCode,
  validateDate,
} from '../utils/validators';
import { getCognitoPublicKeys } from '../utils/cognitoKeys';
import { User } from '../interfaces/user.interface';

export default class AuthService {
  private readonly userPoolId: string;
  private readonly clientId: string;
  private readonly userPoolRegion: string;

  /**
   * Initializes the AuthService with Cognito configuration.
   * @param cognitoConfig - Configuration object containing Cognito details.
   */
  constructor(cognitoConfig: {
    userPoolId: string;
    clientId: string;
    userPoolRegion: string;
  }) {
    this.userPoolId = cognitoConfig.userPoolId;
    this.clientId = cognitoConfig.clientId;
    this.userPoolRegion = cognitoConfig.userPoolRegion;

    if (!this.userPoolId || !this.clientId || !this.userPoolRegion) {
      throw new Error('Cognito configuration is missing.');
    }
  }

  /**
   * Registers a new user with Cognito.
   * @param identifier - The user's email or phone number.
   * @param password - The user's password.
   * @param isEmail - True if the identifier is an email, false if it's a phone number.
   * @returns The Cognito SignUpResponse.
   * @throws CustomError if registration fails or inputs are invalid.
   */
  async register(identifier: string, password: string, isEmail: boolean) {
    // Input validation
    if (!validateIdentifier(identifier, isEmail)) {
      throw new CustomError('Invalid identifier.', 400);
    }
    if (!validatePassword(password)) {
      throw new CustomError('Invalid password.', 400);
    }

    const userAttributes = isEmail
      ? [{ Name: 'email', Value: identifier }]
      : [{ Name: 'phone_number', Value: identifier }];

    const params: SignUpCommandInput = {
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
      this.handleCognitoError(error, 'User registration failed', {
        identifier,
      });
    }
  }

  /**
   * Confirms user sign-up with Cognito and creates a user record in the User-Service.
   * Returns authentication tokens and user data.
   * @param identifier - The user's email or phone number.
   * @param code - The confirmation code received.
   * @param username - The desired username.
   * @param displayName - The user's display name.
   * @param dateOfBirth - The user's date of birth.
   * @param password - The user's password.
   * @returns An object containing tokens and user data.
   * @throws CustomError if confirmation fails or inputs are invalid.
   */
  async confirmSignUp(
    identifier: string,
    code: string,
    username: string,
    displayName: string,
    dateOfBirth: Date,
    password: string
  ) {
    const parsedDateOfBirth = new Date(dateOfBirth);
    // Input validation
    if (!validateIdentifier(identifier, true)) {
      throw new CustomError('Invalid identifier.', 400);
    }
    if (!validateCode(code)) {
      throw new CustomError('Invalid confirmation code.', 400);
    }
    if (!validatePassword(password)) {
      throw new CustomError('Invalid password.', 400);
    }
    if (!validateDate(parsedDateOfBirth)) {
      throw new CustomError('Invalid date of birth.', 400);
    }

    const params: ConfirmSignUpCommandInput = {
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

      if (tokens?.tokens.AccessToken && tokens.tokens.IdToken) {
        Logger.info(`User authenticated successfully for: ${identifier}`);

        // Verify IdToken
        const verifiedIdToken = await this.verifyJwt(tokens.tokens.IdToken);
        const cognitoSub = verifiedIdToken.sub;

        // Create user in User-Service and get the user data
        const user = await this.createUserInUserService(
          {
            cognitoId: cognitoSub,
            username,
            email: identifier,
            displayName: displayName,
            dateOfBirth: parsedDateOfBirth,
          },
          tokens.tokens.AccessToken
        );

        return {
          tokens: tokens.tokens,
          user,
        };
      } else {
        Logger.error(
          `Authentication failed for: ${identifier}. No tokens returned.`
        );
        throw new CustomError(
          'Authentication failed. Tokens not received.',
          401
        );
      }
    } catch (error) {
      this.handleCognitoError(
        error,
        'User confirmation/authentication failed',
        {
          identifier,
        }
      );
    }
  }

  /**
   * Logs in a user using AWS Cognito AdminInitiateAuthCommand.
   * @param identifier - User's email or phone number.
   * @param password - User's password.
   * @returns Authentication result containing tokens.
   * @throws CustomError with appropriate message and status code.
   */
  async login(identifier: string, password: string) {
    // Input validation
    if (!validateIdentifier(identifier, true)) {
      throw new CustomError('Invalid identifier.', 400);
    }
    if (!validatePassword(password)) {
      throw new CustomError('Invalid password.', 400);
    }

    const params: AdminInitiateAuthCommandInput = {
      UserPoolId: this.userPoolId,
      ClientId: this.clientId,
      AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
      AuthParameters: {
        USERNAME: identifier,
        PASSWORD: password,
      },
    };

    try {
      const command = new AdminInitiateAuthCommand(params);
      const response = await cognitoClient.send(command);

      if (response.AuthenticationResult) {
        Logger.info(`User login successful for identifier: ${identifier}`);
        const tokens = response.AuthenticationResult;

        // Verify IdToken
        // const verifiedIdToken = await this.verifyJwt(tokens.IdToken!);
        // const cognitoSub = verifiedIdToken.sub;

        // // Get user data from User-Service
        // const user = await this.getUserFromUserService(
        //   cognitoSub,
        //   tokens.AccessToken!
        // );

        return {
          tokens,
        };
      } else {
        Logger.warn(
          `AuthenticationResult is undefined for identifier: ${identifier}`
        );
        throw new CustomError(
          'Authentication failed. No tokens received.',
          401
        );
      }
    } catch (error) {
      this.handleCognitoError(error, 'User login failed', {
        identifier,
      });
    }
  }

  /**
   * Refreshes authentication tokens using a refresh token.
   * @param refreshToken - The refresh token.
   * @returns New authentication tokens.
   * @throws CustomError if token refresh fails.
   */
  async refreshToken(refreshToken: string) {
    // Input validation
    if (!refreshToken) {
      throw new CustomError('Refresh token is required.', 400);
    }

    const params: InitiateAuthCommandInput = {
      AuthFlow: AuthFlowType.REFRESH_TOKEN_AUTH,
      ClientId: this.clientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
      },
    };

    try {
      const command = new InitiateAuthCommand(params);
      const response = await cognitoClient.send(command);

      if (response.AuthenticationResult) {
        Logger.info('Token refreshed successfully');
        return response.AuthenticationResult;
      } else {
        Logger.warn('Token refresh failed. No tokens received.');
        throw new CustomError('Token refresh failed.', 400);
      }
    } catch (error) {
      this.handleCognitoError(error, 'Token refresh failed');
    }
  }

  /**
   * Initiates a password reset process for a user.
   * @param identifier - User's email or phone number.
   * @throws CustomError if initiation fails.
   */
  async initiatePasswordReset(identifier: string) {
    // Input validation
    if (!validateIdentifier(identifier, true)) {
      throw new CustomError('Invalid identifier.', 400);
    }

    const params: ForgotPasswordCommandInput = {
      ClientId: this.clientId,
      Username: identifier,
    };

    try {
      const command = new ForgotPasswordCommand(params);
      await cognitoClient.send(command);
      Logger.info(`Password reset initiated for identifier: ${identifier}`);
    } catch (error) {
      this.handleCognitoError(error, 'Password reset initiation failed', {
        identifier,
      });
    }
  }

  /**
   * Confirms a password reset with a confirmation code.
   * @param identifier - User's email or phone number.
   * @param code - Confirmation code received.
   * @param newPassword - New password to set.
   * @throws CustomError if confirmation fails.
   */
  async confirmPasswordReset(
    identifier: string,
    code: string,
    newPassword: string
  ) {
    // Input validation
    if (!validateIdentifier(identifier, true)) {
      throw new CustomError('Invalid identifier.', 400);
    }
    if (!validateCode(code)) {
      throw new CustomError('Invalid confirmation code.', 400);
    }
    if (!validatePassword(newPassword)) {
      throw new CustomError('Invalid password.', 400);
    }

    const params: ConfirmForgotPasswordCommandInput = {
      ClientId: this.clientId,
      Username: identifier,
      ConfirmationCode: code,
      Password: newPassword,
    };

    try {
      const command = new ConfirmForgotPasswordCommand(params);
      await cognitoClient.send(command);
      Logger.info(`Password reset confirmed for identifier: ${identifier}`);
    } catch (error) {
      this.handleCognitoError(error, 'Password reset confirmation failed', {
        identifier,
      });
    }
  }

  /**
   * Handles errors from Cognito and throws standardized CustomError instances.
   * @param error - The error object caught.
   * @param defaultMessage - Default error message.
   * @param context - Additional context for logging.
   * @throws CustomError with standardized message and status code.
   */
  private handleCognitoError(
    error: unknown,
    defaultMessage: string,
    context?: Record<string, any>
  ): never {
    if (error instanceof CognitoIdentityProviderServiceException) {
      let message = error.message || defaultMessage;
      let status = 400;

      switch (error.name) {
        case 'UsernameExistsException':
          message = 'User already exists';
          status = 409;
          break;
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
          status = 404;
          break;
        case 'TooManyFailedAttemptsException':
          message = 'Too many failed attempts. Please try again later.';
          status = 429;
          break;
        case 'TooManyRequestsException':
          message = 'Too many requests. Please try again later.';
          status = 429;
          break;
        case 'UserNotConfirmedException':
          message =
            'User not confirmed. Please check your email for confirmation instructions.';
          status = 401;
          break;
        default:
          message = defaultMessage;
      }

      Logger.error(`${defaultMessage} for identifier: ${context?.identifier}`, {
        error: error.message,
        code: error.name,
        ...context,
      });
      throw new CustomError(message, status);
    } else {
      Logger.error(`Unexpected error: ${defaultMessage}`, {
        error,
        ...context,
      });
      throw new CustomError('An unexpected error occurred.', 500);
    }
  }

  /**
   * Creates a user record in the User-Service with retry logic.
   * Returns the user data received from the User-Service.
   * @param userData - The user data to send.
   * @param accessToken - Access token for authorization.
   * @returns The created user data.
   * @throws CustomError if the operation fails after retries.
   */
  private async createUserInUserService(
    userData: {
      cognitoId: string;
      username: string;
      displayName: string;
      email?: string;
      mobile?: string;
      dateOfBirth: Date;
    },
    accessToken: string
  ): Promise<User> {
    return await retry(
      async (bail, attempt) => {
        try {
          const response: AxiosResponse<User> = await apiClient.post(
            '/users',
            userData,
            {
              headers: {
                Authorization: `Bearer ${accessToken}`,
              },
            }
          );
          Logger.info(
            `User record created in User-Service for cognito_sub: ${userData.cognitoId}`,
            { responseStatus: response.status, attempt }
          );
          return response.data;
        } catch (error: any) {
          if (error.response && error.response.status < 500) {
            // Do not retry on client errors
            bail(error);
            return;
          }
          Logger.warn(
            `Attempt ${attempt} failed to create user in User-Service for cognito_sub: ${userData.cognitoId}`,
            { error }
          );
          throw error;
        }
      },
      {
        retries: 3,
        minTimeout: 1000,
        maxTimeout: 5000,
        onRetry: (error, attempt) => {
          Logger.info(
            `Retrying to create user in User-Service. Attempt ${attempt}`
          );
        },
      }
    ).catch(error => {
      Logger.error(
        `Failed to create user in User-Service after retries for cognito_sub: ${userData.cognitoId}`,
        { error }
      );
      throw new CustomError('Failed to create user in User-Service.', 500);
    });
  }

  private async getUserFromUserService(
    id: string,
    accessToken: string
  ): Promise<User> {
    try {
      const response: AxiosResponse<User> = await apiClient.get(
        `/users/${id}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );
      Logger.info(`User data retrieved from User-Service for ID: ${id}`, {
        responseStatus: response.status,
      });
      return response.data;
    } catch (error) {
      Logger.error(
        `Failed to retrieve user data from User-Service for ID: ${id}`,
        {
          error,
        }
      );
      throw new CustomError('Failed to retrieve user data.', 500);
    }
  }

  /**
   * Verifies a JWT token using Cognito's public keys.
   * @param token - The JWT token to verify.
   * @returns The verified token payload.
   * @throws CustomError if verification fails.
   */
  private async verifyJwt(token: string): Promise<any> {
    const decodedToken = jwt.decode(token, { complete: true });
    if (!decodedToken || typeof decodedToken === 'string') {
      throw new CustomError('Invalid token.', 401);
    }

    const kid = decodedToken.header.kid;

    const keys = await getCognitoPublicKeys(
      this.userPoolId,
      this.userPoolRegion
    );

    const key = keys[kid!];

    if (!key) {
      Logger.error(`No matching key found for kid: ${kid}`);
      throw new CustomError('Invalid token key ID.', 401);
    }

    try {
      const verifiedToken = jwt.verify(token, key.pem, {
        algorithms: ['RS256'],
        issuer: `https://cognito-idp.${this.userPoolRegion}.amazonaws.com/${this.userPoolId}`,
        audience: this.clientId,
      });
      return verifiedToken;
    } catch (error) {
      Logger.error('Token verification failed', { error });
      throw new CustomError('Invalid token.', 401);
    }
  }
}
