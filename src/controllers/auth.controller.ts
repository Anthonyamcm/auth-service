import { Router, Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/auth.service';
import { LoginDto } from '../dtos/login.dto';
import { RefreshDto } from '../dtos/refresh.dto';
import { ForgotPasswordDto } from '../dtos/forgotPassword.dto';
import { ConfirmDto } from '../dtos/confirm.dto';
import { RegisterDto } from '../dtos/register.dto';
import { ResetPasswordDto } from '../dtos/resetPassword.dto';
import { validationMiddleware } from '../middlewares/validation.middleware';

const router = Router();
const authService = new AuthService();

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: API endpoints for user authentication
 */

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       description: User registration data
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterDto'
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Bad request
 */
router.post(
  '/register',
  validationMiddleware(RegisterDto),
  async (req: Request, res: Response, next: NextFunction) => {
    const { identifier, password, isEmail } = req.body;
    try {
      await authService.register(identifier, password, isEmail);
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /auth/confirm:
 *   post:
 *     summary: Confirm user registration
 *     tags: [Authentication]
 *     requestBody:
 *       description: Confirmation data
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ConfirmDto'
 *     responses:
 *       200:
 *         description: User confirmed successfully
 *       400:
 *         description: Bad request
 */
router.post(
  '/confirm',
  validationMiddleware(ConfirmDto),
  async (req: Request, res: Response, next: NextFunction) => {
    const { identifier, code, password, displayName, username } = req.body;
    try {
      const result = await authService.confirmSignUp(
        identifier,
        code,
        username,
        displayName,
        password
      );
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login a user
 *     tags: [Authentication]
 *     requestBody:
 *       description: User login data
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginDto'
 *     responses:
 *       200:
 *         description: Login successful
 *       400:
 *         description: Bad request
 */
router.post(
  '/login',
  validationMiddleware(LoginDto),
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;
    try {
      const result = await authService.login(email, password);
      res.status(200).json({
        accessToken: result?.AccessToken,
        refreshToken: result?.RefreshToken,
        idToken: result?.IdToken,
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Authentication]
 *     requestBody:
 *       description: Refresh token data
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RefreshDto'
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       400:
 *         description: Bad request
 */
router.post(
  '/refresh',
  validationMiddleware(RefreshDto),
  async (req: Request, res: Response, next: NextFunction) => {
    const { refreshToken } = req.body;
    try {
      const result = await authService.refreshToken(refreshToken);
      res.status(200).json({
        message: 'Token refreshed successfully',
        accessToken: result?.AccessToken,
        idToken: result?.IdToken,
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *     summary: Initiate password reset
 *     tags: [Authentication]
 *     requestBody:
 *       description: User email for password reset
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ForgotPasswordDto'
 *     responses:
 *       200:
 *         description: Password reset initiated successfully
 *       400:
 *         description: Bad request
 */
router.post(
  '/forgot-password',
  validationMiddleware(ForgotPasswordDto),
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;
    try {
      await authService.initiatePasswordReset(email);
      res
        .status(200)
        .json({ message: 'Password reset initiated successfully' });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     summary: Confirm password reset
 *     tags: [Authentication]
 *     requestBody:
 *       description: Password reset confirmation data
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ResetPasswordDto'
 *     responses:
 *       200:
 *         description: Password reset confirmed successfully
 *       400:
 *         description: Bad request
 */
router.post(
  '/reset-password',
  validationMiddleware(ResetPasswordDto),
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, code, newPassword } = req.body;
    try {
      await authService.confirmPasswordReset(email, code, newPassword);
      res
        .status(200)
        .json({ message: 'Password reset confirmed successfully' });
    } catch (error) {
      next(error);
    }
  }
);

export default router;
