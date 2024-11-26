import { Router, Request, Response, NextFunction } from 'express';
import AuthService from '../services/auth.service';
import { CustomError } from '../middlewares/error.middleware';

declare global {
  namespace Express {
    interface Request {
      authService: AuthService;
    }
  }
}

const router = Router();

router.use((req: Request, res: Response, next: NextFunction) => {
  const authService: AuthService = req.app.locals.authService;
  if (!authService) {
    return next(new CustomError('AuthService is not initialized.', 500));
  }
  req.authService = authService;
  next();
});

// Register Route
router.post(
  '/register',
  async (req: Request, res: Response, next: NextFunction) => {
    const { identifier, password, isEmail } = req.body;
    try {
      const response = await req.authService.register(
        identifier,
        password,
        isEmail
      );
      res.status(200).json(response);
    } catch (error) {
      next(error);
    }
  }
);

// Confirm Sign-Up Route
router.post(
  '/confirm-signup',
  async (req: Request, res: Response, next: NextFunction) => {
    const { identifier, code, username, displayName, dateOfBirth, password } =
      req.body;
    try {
      const result = await req.authService.confirmSignUp(
        identifier,
        code,
        username,
        displayName,
        dateOfBirth,
        password
      );
      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  }
);

// Login Route
router.post(
  '/login',
  async (req: Request, res: Response, next: NextFunction) => {
    const { identifier, password } = req.body;
    try {
      const tokens = await req.authService.login(identifier, password);
      res.status(200).json(tokens);
    } catch (error) {
      next(error);
    }
  }
);

// Refresh Token Route
router.post(
  '/refresh-token',
  async (req: Request, res: Response, next: NextFunction) => {
    const { refreshToken } = req.body;
    try {
      const tokens = await req.authService.refreshToken(refreshToken);
      res.status(200).json(tokens);
    } catch (error) {
      next(error);
    }
  }
);

// Initiate Password Reset
router.post(
  '/password-reset/initiate',
  async (req: Request, res: Response, next: NextFunction) => {
    const { identifier } = req.body;
    try {
      await req.authService.initiatePasswordReset(identifier);
      res.status(200).json({ message: 'Password reset initiated.' });
    } catch (error) {
      next(error);
    }
  }
);

// Confirm Password Reset
router.post(
  '/password-reset/confirm',
  async (req: Request, res: Response, next: NextFunction) => {
    const { identifier, code, newPassword } = req.body;
    try {
      await req.authService.confirmPasswordReset(identifier, code, newPassword);
      res.status(200).json({ message: 'Password reset confirmed.' });
    } catch (error) {
      next(error);
    }
  }
);

export default router;
