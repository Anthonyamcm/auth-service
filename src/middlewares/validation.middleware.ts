import { plainToInstance } from 'class-transformer';
import { validate, ValidationError } from 'class-validator';
import { Request, Response, NextFunction } from 'express';

export const validationMiddleware = (type: any) => {
  return (req: Request, res: Response, next: NextFunction) => {
    validate(plainToInstance(type, req.body), {
      skipMissingProperties: false,
    }).then((errors: ValidationError[]) => {
      if (errors.length > 0) {
        const messages = errors
          .map((error: ValidationError) => Object.values(error.constraints!))
          .join(', ');
        res.status(400).json({ errors: messages });
      } else {
        next();
      }
    });
  };
};
