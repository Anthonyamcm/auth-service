import { Request, Response, NextFunction } from 'express';
import AuthService from '../services/auth.service';

export function authServiceReady(authService: AuthService) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!authService) {
      res.status(500).json({ message: 'AuthService is not initialized.' });
    } else {
      next();
    }
  };
}
