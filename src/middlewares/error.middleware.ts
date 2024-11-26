import { Request, Response, NextFunction } from 'express';
import Logger from '../utils/logger';

export class CustomError extends Error {
  public status: number;

  constructor(message: string, status: number = 500) {
    super(message);
    this.status = status;
  }
}

export default function errorMiddleware(
  err: CustomError,
  req: Request,
  res: Response,
  next: NextFunction
) {
  const status = err.status || 500;
  const message = err.message || 'Something went wrong';

  Logger.error(`Error: ${message}`, {
    status,
    stack: err.stack,
  });

  res.status(status).json({
    status,
    message,
  });
}
