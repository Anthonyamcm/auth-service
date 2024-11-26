import AuthService from '../services/auth.service';

declare global {
  namespace Express {
    interface Request {
      authService: AuthService;
    }
  }
}
